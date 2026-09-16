rule TTP_XOR_WriteProcessMemory_eee0 {
  strings:
    $key_eee0 = { b9 92 [2] 8b b0 [2] 8d 85 [2] a3 85 [2] 9c 99 }

  condition:
    any of them
}