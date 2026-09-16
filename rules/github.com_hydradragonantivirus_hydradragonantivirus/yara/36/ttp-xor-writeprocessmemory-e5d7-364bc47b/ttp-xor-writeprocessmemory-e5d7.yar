rule TTP_XOR_WriteProcessMemory_e5d7 {
  strings:
    $key_e5d7 = { b2 a5 [2] 80 87 [2] 86 b2 [2] a8 b2 [2] 97 ae }

  condition:
    any of them
}