rule TTP_XOR_WriteProcessMemory_428b {
  strings:
    $key_428b = { 15 f9 [2] 27 db [2] 21 ee [2] 0f ee [2] 30 f2 }

  condition:
    any of them
}