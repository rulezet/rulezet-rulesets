rule TTP_XOR_WriteProcessMemory_6ec3 {
  strings:
    $key_6ec3 = { 39 b1 [2] 0b 93 [2] 0d a6 [2] 23 a6 [2] 1c ba }

  condition:
    any of them
}