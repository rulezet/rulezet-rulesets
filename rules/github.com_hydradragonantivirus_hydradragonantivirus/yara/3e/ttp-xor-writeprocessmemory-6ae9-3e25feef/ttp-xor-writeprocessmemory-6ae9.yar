rule TTP_XOR_WriteProcessMemory_6ae9 {
  strings:
    $key_6ae9 = { 3d 9b [2] 0f b9 [2] 09 8c [2] 27 8c [2] 18 90 }

  condition:
    any of them
}