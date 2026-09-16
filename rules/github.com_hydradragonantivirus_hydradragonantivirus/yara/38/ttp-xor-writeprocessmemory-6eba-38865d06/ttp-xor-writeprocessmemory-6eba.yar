rule TTP_XOR_WriteProcessMemory_6eba {
  strings:
    $key_6eba = { 39 c8 [2] 0b ea [2] 0d df [2] 23 df [2] 1c c3 }

  condition:
    any of them
}