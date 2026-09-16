rule TTP_XOR_WriteProcessMemory_1ad7 {
  strings:
    $key_1ad7 = { 4d a5 [2] 7f 87 [2] 79 b2 [2] 57 b2 [2] 68 ae }

  condition:
    any of them
}