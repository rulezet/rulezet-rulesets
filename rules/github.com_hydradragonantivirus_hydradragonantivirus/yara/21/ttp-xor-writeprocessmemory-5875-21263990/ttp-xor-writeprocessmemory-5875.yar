rule TTP_XOR_WriteProcessMemory_5875 {
  strings:
    $key_5875 = { 0f 07 [2] 3d 25 [2] 3b 10 [2] 15 10 [2] 2a 0c }

  condition:
    any of them
}