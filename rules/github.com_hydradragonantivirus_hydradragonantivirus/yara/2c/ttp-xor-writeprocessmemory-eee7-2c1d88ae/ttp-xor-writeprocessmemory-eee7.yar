rule TTP_XOR_WriteProcessMemory_eee7 {
  strings:
    $key_eee7 = { b9 95 [2] 8b b7 [2] 8d 82 [2] a3 82 [2] 9c 9e }

  condition:
    any of them
}