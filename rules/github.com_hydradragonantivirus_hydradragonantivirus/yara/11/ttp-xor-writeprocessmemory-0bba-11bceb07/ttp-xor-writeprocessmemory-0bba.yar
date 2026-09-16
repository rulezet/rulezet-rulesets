rule TTP_XOR_WriteProcessMemory_0bba {
  strings:
    $key_0bba = { 5c c8 [2] 6e ea [2] 68 df [2] 46 df [2] 79 c3 }

  condition:
    any of them
}