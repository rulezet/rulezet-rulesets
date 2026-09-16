rule TTP_XOR_WriteProcessMemory_4824 {
  strings:
    $key_4824 = { 1f 56 [2] 2d 74 [2] 2b 41 [2] 05 41 [2] 3a 5d }

  condition:
    any of them
}