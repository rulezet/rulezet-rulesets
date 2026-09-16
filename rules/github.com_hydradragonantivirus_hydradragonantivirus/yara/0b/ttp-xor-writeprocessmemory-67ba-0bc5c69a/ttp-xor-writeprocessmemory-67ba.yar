rule TTP_XOR_WriteProcessMemory_67ba {
  strings:
    $key_67ba = { 30 c8 [2] 02 ea [2] 04 df [2] 2a df [2] 15 c3 }

  condition:
    any of them
}