rule TTP_XOR_WriteProcessMemory_6892 {
  strings:
    $key_6892 = { 3f e0 [2] 0d c2 [2] 0b f7 [2] 25 f7 [2] 1a eb }

  condition:
    any of them
}