rule TTP_XOR_WriteProcessMemory_07ba {
  strings:
    $key_07ba = { 50 c8 [2] 62 ea [2] 64 df [2] 4a df [2] 75 c3 }

  condition:
    any of them
}