rule AcidBox_SSP_DLL_Loader_Format_String_Chunk {
  meta:
    description = "Detects AcidBox SSP DLL loaders, based on a unique string chunk of format strings"
    author      = "BitsOfBinary"
    reference   = "https://unit42.paloaltonetworks.com/acidbox-rare-malware/"
    hash        = "003669761229d3e1db0f5a5b333ef62b3dffcc8e27c821ce9018362e0a2df7e9"
    version     = "1.0"
    date        = "2023-03-20"
    DaysofYARA  = "79/100"

  strings:
                $ = { 25 73 5C 25 73 00 00 00 00 00 00 00 25 73 5C 25 73 7B 25 73 7D 00 00 00 00 00 00 00 25 73 5C 7B 25 73 7D 00 }

  condition:
    any of them
}