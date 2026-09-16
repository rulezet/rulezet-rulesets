rule TTP_XOR_WriteProcessMemory_7624 {
  strings:
    $key_7624 = { 21 56 [2] 13 74 [2] 15 41 [2] 3b 41 [2] 04 5d }

  condition:
    any of them
}