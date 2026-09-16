rule TTP_XOR_WriteProcessMemory_6cba {
  strings:
    $key_6cba = { 3b c8 [2] 09 ea [2] 0f df [2] 21 df [2] 1e c3 }

  condition:
    any of them
}