rule TTP_XOR_WriteProcessMemory_59a8 {
  strings:
    $key_59a8 = { 0e da [2] 3c f8 [2] 3a cd [2] 14 cd [2] 2b d1 }

  condition:
    any of them
}