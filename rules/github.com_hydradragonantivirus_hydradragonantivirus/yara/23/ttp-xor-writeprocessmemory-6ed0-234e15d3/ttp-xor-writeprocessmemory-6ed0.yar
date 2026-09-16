rule TTP_XOR_WriteProcessMemory_6ed0 {
  strings:
    $key_6ed0 = { 39 a2 [2] 0b 80 [2] 0d b5 [2] 23 b5 [2] 1c a9 }

  condition:
    any of them
}