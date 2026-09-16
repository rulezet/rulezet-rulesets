rule TTP_XOR_WriteProcessMemory_5835 {
  strings:
    $key_5835 = { 0f 47 [2] 3d 65 [2] 3b 50 [2] 15 50 [2] 2a 4c }

  condition:
    any of them
}