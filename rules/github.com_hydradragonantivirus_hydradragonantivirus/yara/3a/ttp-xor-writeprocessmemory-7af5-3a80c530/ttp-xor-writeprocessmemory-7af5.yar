rule TTP_XOR_WriteProcessMemory_7af5 {
  strings:
    $key_7af5 = { 2d 87 [2] 1f a5 [2] 19 90 [2] 37 90 [2] 08 8c }

  condition:
    any of them
}