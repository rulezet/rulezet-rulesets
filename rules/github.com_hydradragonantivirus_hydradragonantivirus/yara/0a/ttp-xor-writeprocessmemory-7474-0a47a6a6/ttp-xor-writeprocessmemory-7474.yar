rule TTP_XOR_WriteProcessMemory_7474 {
  strings:
    $key_7474 = { 23 06 [2] 11 24 [2] 17 11 [2] 39 11 [2] 06 0d }

  condition:
    any of them
}