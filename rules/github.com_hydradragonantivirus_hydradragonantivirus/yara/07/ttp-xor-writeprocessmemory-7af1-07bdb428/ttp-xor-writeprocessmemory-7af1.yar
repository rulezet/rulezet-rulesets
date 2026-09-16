rule TTP_XOR_WriteProcessMemory_7af1 {
  strings:
    $key_7af1 = { 2d 83 [2] 1f a1 [2] 19 94 [2] 37 94 [2] 08 88 }

  condition:
    any of them
}