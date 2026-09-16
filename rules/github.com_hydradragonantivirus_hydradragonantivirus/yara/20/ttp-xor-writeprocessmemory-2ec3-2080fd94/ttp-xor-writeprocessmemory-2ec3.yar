rule TTP_XOR_WriteProcessMemory_2ec3 {
  strings:
    $key_2ec3 = { 79 b1 [2] 4b 93 [2] 4d a6 [2] 63 a6 [2] 5c ba }

  condition:
    any of them
}