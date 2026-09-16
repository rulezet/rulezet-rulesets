rule TTP_XOR_WriteProcessMemory_71e3 {
  strings:
    $key_71e3 = { 26 91 [2] 14 b3 [2] 12 86 [2] 3c 86 [2] 03 9a }

  condition:
    any of them
}