rule TTP_XOR_WriteProcessMemory_aacc {
  strings:
    $key_aacc = { fd be [2] cf 9c [2] c9 a9 [2] e7 a9 [2] d8 b5 }

  condition:
    any of them
}