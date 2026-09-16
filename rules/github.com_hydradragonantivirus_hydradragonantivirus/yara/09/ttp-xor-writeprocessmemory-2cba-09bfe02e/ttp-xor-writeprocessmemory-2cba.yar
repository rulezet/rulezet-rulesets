rule TTP_XOR_WriteProcessMemory_2cba {
  strings:
    $key_2cba = { 7b c8 [2] 49 ea [2] 4f df [2] 61 df [2] 5e c3 }

  condition:
    any of them
}