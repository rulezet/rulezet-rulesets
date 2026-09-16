rule TTP_XOR_WriteProcessMemory_c0d7 {
  strings:
    $key_c0d7 = { 97 a5 [2] a5 87 [2] a3 b2 [2] 8d b2 [2] b2 ae }

  condition:
    any of them
}