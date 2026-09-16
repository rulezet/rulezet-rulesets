rule TTP_XOR_WriteProcessMemory_3ec3 {
  strings:
    $key_3ec3 = { 69 b1 [2] 5b 93 [2] 5d a6 [2] 73 a6 [2] 4c ba }

  condition:
    any of them
}