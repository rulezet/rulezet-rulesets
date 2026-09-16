rule TTP_XOR_WriteProcessMemory_e7d7 {
  strings:
    $key_e7d7 = { b0 a5 [2] 82 87 [2] 84 b2 [2] aa b2 [2] 95 ae }

  condition:
    any of them
}