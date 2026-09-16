rule TTP_XOR_WriteProcessMemory_f476 {
  strings:
    $key_f476 = { a3 04 [2] 91 26 [2] 97 13 [2] b9 13 [2] 86 0f }

  condition:
    any of them
}