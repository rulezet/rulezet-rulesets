rule TTP_XOR_WriteProcessMemory_6a25 {
  strings:
    $key_6a25 = { 3d 57 [2] 0f 75 [2] 09 40 [2] 27 40 [2] 18 5c }

  condition:
    any of them
}