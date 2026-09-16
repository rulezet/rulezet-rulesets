rule TTP_XOR_WriteProcessMemory_4e35 {
  strings:
    $key_4e35 = { 19 47 [2] 2b 65 [2] 2d 50 [2] 03 50 [2] 3c 4c }

  condition:
    any of them
}