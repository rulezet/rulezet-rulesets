rule pelles_c_290_300_400_dll_x86_crtlib {
  meta:
    author      = "PEiD"
    description = "Pelles C 2.90, 3.00, 4.00 DLL (X86 CRT-LIB)"
    group       = "444"
    function    = "0"

  strings:
    $a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 BF 01 00 00 00 85 DB 75 10 83 3D ?? ?? ?? ?? 00 75 07 31 C0 E9 ?? ?? ?? ?? 83 FB 01 74 05 83 FB 02 75 ?? 85 FF 74 }

  condition:
    $a0
}