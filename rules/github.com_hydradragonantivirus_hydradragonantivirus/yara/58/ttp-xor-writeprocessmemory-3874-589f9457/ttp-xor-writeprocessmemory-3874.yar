rule TTP_XOR_WriteProcessMemory_3874 {
  strings:
    $key_3874 = { 6f 06 [2] 5d 24 [2] 5b 11 [2] 75 11 [2] 4a 0d }

  condition:
    any of them
}