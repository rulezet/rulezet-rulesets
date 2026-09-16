rule TTP_XOR_WriteProcessMemory_eed2 {
  strings:
    $key_eed2 = { b9 a0 [2] 8b 82 [2] 8d b7 [2] a3 b7 [2] 9c ab }

  condition:
    any of them
}