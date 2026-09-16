rule TTP_XOR_WriteProcessMemory_5ae1 {
  strings:
    $key_5ae1 = { 0d 93 [2] 3f b1 [2] 39 84 [2] 17 84 [2] 28 98 }

  condition:
    any of them
}