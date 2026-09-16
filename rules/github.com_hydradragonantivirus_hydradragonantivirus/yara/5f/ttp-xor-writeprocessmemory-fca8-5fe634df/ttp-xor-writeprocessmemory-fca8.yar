rule TTP_XOR_WriteProcessMemory_fca8 {
  strings:
    $key_fca8 = { ab da [2] 99 f8 [2] 9f cd [2] b1 cd [2] 8e d1 }

  condition:
    any of them
}