rule TTP_XOR_WriteProcessMemory_7af2 {
  strings:
    $key_7af2 = { 2d 80 [2] 1f a2 [2] 19 97 [2] 37 97 [2] 08 8b }

  condition:
    any of them
}