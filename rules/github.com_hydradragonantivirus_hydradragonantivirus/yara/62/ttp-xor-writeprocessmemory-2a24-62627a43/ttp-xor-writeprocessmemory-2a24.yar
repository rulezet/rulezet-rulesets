rule TTP_XOR_WriteProcessMemory_2a24 {
  strings:
    $key_2a24 = { 7d 56 [2] 4f 74 [2] 49 41 [2] 67 41 [2] 58 5d }

  condition:
    any of them
}