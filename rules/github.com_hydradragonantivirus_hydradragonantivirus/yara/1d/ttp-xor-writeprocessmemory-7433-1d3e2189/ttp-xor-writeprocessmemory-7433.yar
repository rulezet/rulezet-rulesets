rule TTP_XOR_WriteProcessMemory_7433 {
  strings:
    $key_7433 = { 23 41 [2] 11 63 [2] 17 56 [2] 39 56 [2] 06 4a }

  condition:
    any of them
}