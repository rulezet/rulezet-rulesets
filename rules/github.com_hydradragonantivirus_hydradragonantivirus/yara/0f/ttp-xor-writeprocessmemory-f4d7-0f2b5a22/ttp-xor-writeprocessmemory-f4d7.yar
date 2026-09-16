rule TTP_XOR_WriteProcessMemory_f4d7 {
  strings:
    $key_f4d7 = { a3 a5 [2] 91 87 [2] 97 b2 [2] b9 b2 [2] 86 ae }

  condition:
    any of them
}