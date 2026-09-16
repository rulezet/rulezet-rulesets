rule TTP_XOR_WriteProcessMemory_eee6 {
  strings:
    $key_eee6 = { b9 94 [2] 8b b6 [2] 8d 83 [2] a3 83 [2] 9c 9f }

  condition:
    any of them
}