rule TTP_XOR_WriteProcessMemory_6a12 {
  strings:
    $key_6a12 = { 3d 60 [2] 0f 42 [2] 09 77 [2] 27 77 [2] 18 6b }

  condition:
    any of them
}