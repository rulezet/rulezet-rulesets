rule TTP_XOR_WriteProcessMemory_6ae7 {
  strings:
    $key_6ae7 = { 3d 95 [2] 0f b7 [2] 09 82 [2] 27 82 [2] 18 9e }

  condition:
    any of them
}