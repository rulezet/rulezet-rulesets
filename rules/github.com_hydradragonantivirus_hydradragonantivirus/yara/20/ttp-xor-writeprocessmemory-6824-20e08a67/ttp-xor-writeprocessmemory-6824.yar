rule TTP_XOR_WriteProcessMemory_6824 {
  strings:
    $key_6824 = { 3f 56 [2] 0d 74 [2] 0b 41 [2] 25 41 [2] 1a 5d }

  condition:
    any of them
}