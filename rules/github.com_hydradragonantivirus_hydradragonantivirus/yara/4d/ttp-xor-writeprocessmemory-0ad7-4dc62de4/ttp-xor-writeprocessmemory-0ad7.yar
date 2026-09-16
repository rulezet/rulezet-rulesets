rule TTP_XOR_WriteProcessMemory_0ad7 {
  strings:
    $key_0ad7 = { 5d a5 [2] 6f 87 [2] 69 b2 [2] 47 b2 [2] 78 ae }

  condition:
    any of them
}