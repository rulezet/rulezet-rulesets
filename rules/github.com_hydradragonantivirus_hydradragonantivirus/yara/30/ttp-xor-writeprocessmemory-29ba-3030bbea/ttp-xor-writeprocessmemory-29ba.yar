rule TTP_XOR_WriteProcessMemory_29ba {
  strings:
    $key_29ba = { 7e c8 [2] 4c ea [2] 4a df [2] 64 df [2] 5b c3 }

  condition:
    any of them
}