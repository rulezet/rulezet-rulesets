rule TTP_XOR_WriteProcessMemory_5473 {
  strings:
    $key_5473 = { 03 01 [2] 31 23 [2] 37 16 [2] 19 16 [2] 26 0a }

  condition:
    any of them
}