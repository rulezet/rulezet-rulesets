rule TTP_XOR_WriteProcessMemory_eeba {
  strings:
    $key_eeba = { b9 c8 [2] 8b ea [2] 8d df [2] a3 df [2] 9c c3 }

  condition:
    any of them
}