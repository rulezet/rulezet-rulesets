rule TTP_XOR_WriteProcessMemory_24d7 {
  strings:
    $key_24d7 = { 73 a5 [2] 41 87 [2] 47 b2 [2] 69 b2 [2] 56 ae }

  condition:
    any of them
}