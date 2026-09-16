rule TTP_XOR_WriteProcessMemory_6ae1 {
  strings:
    $key_6ae1 = { 3d 93 [2] 0f b1 [2] 09 84 [2] 27 84 [2] 18 98 }

  condition:
    any of them
}