rule TTP_XOR_WriteProcessMemory_118d {
  strings:
    $key_118d = { 46 ff [2] 74 dd [2] 72 e8 [2] 5c e8 [2] 63 f4 }

  condition:
    any of them
}