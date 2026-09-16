rule TTP_XOR_WriteProcessMemory_e8d7 {
  strings:
    $key_e8d7 = { bf a5 [2] 8d 87 [2] 8b b2 [2] a5 b2 [2] 9a ae }

  condition:
    any of them
}