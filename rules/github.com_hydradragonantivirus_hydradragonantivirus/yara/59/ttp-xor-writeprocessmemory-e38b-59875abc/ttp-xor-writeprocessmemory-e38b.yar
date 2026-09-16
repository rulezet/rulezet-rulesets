rule TTP_XOR_WriteProcessMemory_e38b {
  strings:
    $key_e38b = { b4 f9 [2] 86 db [2] 80 ee [2] ae ee [2] 91 f2 }

  condition:
    any of them
}