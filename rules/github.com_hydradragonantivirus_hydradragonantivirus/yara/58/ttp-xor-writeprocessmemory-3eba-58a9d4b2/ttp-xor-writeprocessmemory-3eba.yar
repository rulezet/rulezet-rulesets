rule TTP_XOR_WriteProcessMemory_3eba {
  strings:
    $key_3eba = { 69 c8 [2] 5b ea [2] 5d df [2] 73 df [2] 4c c3 }

  condition:
    any of them
}