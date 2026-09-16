rule TTP_XOR_WriteProcessMemory_2eba {
  strings:
    $key_2eba = { 79 c8 [2] 4b ea [2] 4d df [2] 63 df [2] 5c c3 }

  condition:
    any of them
}