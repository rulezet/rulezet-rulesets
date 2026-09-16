rule TTP_XOR_WriteProcessMemory_aadd {
  strings:
    $key_aadd = { fd af [2] cf 8d [2] c9 b8 [2] e7 b8 [2] d8 a4 }

  condition:
    any of them
}