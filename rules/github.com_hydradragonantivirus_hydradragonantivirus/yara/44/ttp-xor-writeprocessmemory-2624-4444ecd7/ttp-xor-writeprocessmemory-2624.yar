rule TTP_XOR_WriteProcessMemory_2624 {
  strings:
    $key_2624 = { 71 56 [2] 43 74 [2] 45 41 [2] 6b 41 [2] 54 5d }

  condition:
    any of them
}