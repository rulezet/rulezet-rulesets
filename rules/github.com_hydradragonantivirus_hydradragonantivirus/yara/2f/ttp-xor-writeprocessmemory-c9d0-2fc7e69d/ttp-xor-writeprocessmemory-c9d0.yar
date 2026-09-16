rule TTP_XOR_WriteProcessMemory_c9d0 {
  strings:
    $key_c9d0 = { 9e a2 [2] ac 80 [2] aa b5 [2] 84 b5 [2] bb a9 }

  condition:
    any of them
}