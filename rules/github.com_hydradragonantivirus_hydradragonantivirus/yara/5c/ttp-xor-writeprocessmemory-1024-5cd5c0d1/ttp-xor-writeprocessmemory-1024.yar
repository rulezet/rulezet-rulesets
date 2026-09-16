rule TTP_XOR_WriteProcessMemory_1024 {
  strings:
    $key_1024 = { 47 56 [2] 75 74 [2] 73 41 [2] 5d 41 [2] 62 5d }

  condition:
    any of them
}