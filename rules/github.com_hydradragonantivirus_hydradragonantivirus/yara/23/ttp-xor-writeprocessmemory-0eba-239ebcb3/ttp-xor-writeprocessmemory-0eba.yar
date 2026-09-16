rule TTP_XOR_WriteProcessMemory_0eba {
  strings:
    $key_0eba = { 59 c8 [2] 6b ea [2] 6d df [2] 43 df [2] 7c c3 }

  condition:
    any of them
}