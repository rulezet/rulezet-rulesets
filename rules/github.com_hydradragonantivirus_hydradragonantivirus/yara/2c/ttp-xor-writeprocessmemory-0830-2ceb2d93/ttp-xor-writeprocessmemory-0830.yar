rule TTP_XOR_WriteProcessMemory_0830 {
  strings:
    $key_0830 = { 5f 42 [2] 6d 60 [2] 6b 55 [2] 45 55 [2] 7a 49 }

  condition:
    any of them
}