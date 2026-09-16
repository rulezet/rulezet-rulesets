rule TTP_XOR_WriteProcessMemory_0cba {
  strings:
    $key_0cba = { 5b c8 [2] 69 ea [2] 6f df [2] 41 df [2] 7e c3 }

  condition:
    any of them
}