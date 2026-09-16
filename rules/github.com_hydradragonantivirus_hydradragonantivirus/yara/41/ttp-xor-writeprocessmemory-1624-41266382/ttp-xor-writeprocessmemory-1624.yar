rule TTP_XOR_WriteProcessMemory_1624 {
  strings:
    $key_1624 = { 41 56 [2] 73 74 [2] 75 41 [2] 5b 41 [2] 64 5d }

  condition:
    any of them
}