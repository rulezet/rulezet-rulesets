rule TTP_XOR_WriteProcessMemory_3146 {
  strings:
    $key_3146 = { 66 34 [2] 54 16 [2] 52 23 [2] 7c 23 [2] 43 3f }

  condition:
    any of them
}