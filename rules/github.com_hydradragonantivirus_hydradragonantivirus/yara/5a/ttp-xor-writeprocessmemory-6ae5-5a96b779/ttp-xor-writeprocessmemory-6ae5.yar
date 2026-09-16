rule TTP_XOR_WriteProcessMemory_6ae5 {
  strings:
    $key_6ae5 = { 3d 97 [2] 0f b5 [2] 09 80 [2] 27 80 [2] 18 9c }

  condition:
    any of them
}