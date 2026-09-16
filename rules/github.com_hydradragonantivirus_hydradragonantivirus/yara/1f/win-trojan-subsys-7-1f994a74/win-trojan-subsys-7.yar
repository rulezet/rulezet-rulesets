rule Win_Trojan_Subsys_7
{
strings:
	$a0 = { 96a20e02bd7551d7fecdf5518bbd85b6b918fef6dd5b043500d9579a7ab17dbecd98ab257bf52276cd9c609cc8292f7e4afa2ef1c82b6795d13df2e366dacfa2369253355e747c9ddb1f103c33d8d1f5 }


condition:
	$a0
}