rule TTP_XOR_WriteProcessMemory_7bba {
  strings:
    $key_7bba = { 2c c8 [2] 1e ea [2] 18 df [2] 36 df [2] 09 c3 }

  condition:
    any of them
}