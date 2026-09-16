rule TTP_XOR_WriteProcessMemory_1fe0 {
  strings:
    $key_1fe0 = { 48 92 [2] 7a b0 [2] 7c 85 [2] 52 85 [2] 6d 99 }

  condition:
    any of them
}