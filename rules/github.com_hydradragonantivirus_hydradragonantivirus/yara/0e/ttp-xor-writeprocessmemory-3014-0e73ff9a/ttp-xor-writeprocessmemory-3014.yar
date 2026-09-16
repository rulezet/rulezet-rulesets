rule TTP_XOR_WriteProcessMemory_3014 {
  strings:
    $key_3014 = { 67 66 [2] 55 44 [2] 53 71 [2] 7d 71 [2] 42 6d }

  condition:
    any of them
}