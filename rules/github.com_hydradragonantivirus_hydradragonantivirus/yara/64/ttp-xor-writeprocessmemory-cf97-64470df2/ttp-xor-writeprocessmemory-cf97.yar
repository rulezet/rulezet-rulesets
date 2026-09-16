rule TTP_XOR_WriteProcessMemory_cf97 {
  strings:
    $key_cf97 = { 98 e5 [2] aa c7 [2] ac f2 [2] 82 f2 [2] bd ee }

  condition:
    any of them
}