rule TTP_XOR_WriteProcessMemory_1067 {
  strings:
    $key_1067 = { 47 15 [2] 75 37 [2] 73 02 [2] 5d 02 [2] 62 1e }

  condition:
    any of them
}