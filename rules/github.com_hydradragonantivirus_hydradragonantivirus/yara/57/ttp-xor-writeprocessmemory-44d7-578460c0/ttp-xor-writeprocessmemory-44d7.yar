rule TTP_XOR_WriteProcessMemory_44d7 {
  strings:
    $key_44d7 = { 13 a5 [2] 21 87 [2] 27 b2 [2] 09 b2 [2] 36 ae }

  condition:
    any of them
}