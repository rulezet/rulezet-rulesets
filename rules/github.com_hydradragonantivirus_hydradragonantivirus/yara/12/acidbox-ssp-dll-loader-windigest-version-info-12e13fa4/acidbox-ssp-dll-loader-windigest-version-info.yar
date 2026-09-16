import "pe"
rule AcidBox_SSP_DLL_Loader_windigest_Version_Info {
  meta:
    description = "Detects AcidBox SSP DLL loaders, based on a unique version information of 'windigest' and a description"
    author      = "BitsOfBinary"
    reference   = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
    reference   = "https://bitsofbinary.github.io/yara/2023/03/24/100daysofyara-day-83.html"
    hash        = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
    version     = "1.0"
    date        = "2023-03-24"
    DaysofYARA  = "83/100"

  condition:
    pe.version_info["InternalName"] == "windigest.dll" or
    pe.version_info["FileDescription"] == "Windows Digest Access"
}