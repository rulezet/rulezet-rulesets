rule TTP_XOR_WriteProcessMemory_aa8d {
  strings:
    $key_aa8d = { fd ff [2] cf dd [2] c9 e8 [2] e7 e8 [2] d8 f4 }

  condition:
    any of them
}