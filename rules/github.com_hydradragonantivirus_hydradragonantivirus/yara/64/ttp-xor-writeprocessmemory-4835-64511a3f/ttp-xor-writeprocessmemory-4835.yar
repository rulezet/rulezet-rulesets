rule TTP_XOR_WriteProcessMemory_4835 {
  strings:
    $key_4835 = { 1f 47 [2] 2d 65 [2] 2b 50 [2] 05 50 [2] 3a 4c }

  condition:
    any of them
}