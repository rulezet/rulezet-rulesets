rule TTP_XOR_WriteProcessMemory_1bba {
  strings:
    $key_1bba = { 4c c8 [2] 7e ea [2] 78 df [2] 56 df [2] 69 c3 }

  condition:
    any of them
}