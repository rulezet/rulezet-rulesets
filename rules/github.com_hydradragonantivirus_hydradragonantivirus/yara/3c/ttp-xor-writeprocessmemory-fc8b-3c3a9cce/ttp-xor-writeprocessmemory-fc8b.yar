rule TTP_XOR_WriteProcessMemory_fc8b {
  strings:
    $key_fc8b = { ab f9 [2] 99 db [2] 9f ee [2] b1 ee [2] 8e f2 }

  condition:
    any of them
}