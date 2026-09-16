rule VM_Detect_VirtualPC_XEN_Wine
{
	meta:
        	author = "Thomas Roccia - @fr0gger_ - Unprotect Project"
        	description = "Xen detection, VirtualPC, Red Pill, Wine and other"
	strings:
        	        	$virtualpc = {0F 3F 07 0B}
        	$ssexy = {66 0F 70 ?? ?? 66 0F DB ?? ?? ?? ?? ?? 66 0F DB ?? ?? ?? ?? ?? 66 0F EF}
        	$vmcheckdll = {45 C7 00 01}
        	$redpill = {0F 01 0D 00 00 00 00 C3}

        	$virtualpc1 = "vpcbus" nocase
        	$virtualpc2 = "vpc-s3" nocase
        	$virtualpc3 = "vpcuhub" nocase
        	$virtualpc4 = "msvmmouf" nocase

        	$xen1 = "xenevtchn" nocase
        	$xen2 = "xennet" nocase
        	$xen3 = "xennet6" nocase
        	$xen4 = "xensvc" nocase
        	$xen5 = "xenvdb" nocase
        	$xen6 = "XenVMM" nocase
        	$xen7 = "xenservice.exe" nocase

        	$wine1 = "wine_get_unix_file_name" ascii wide
	condition:
        	any of them
}