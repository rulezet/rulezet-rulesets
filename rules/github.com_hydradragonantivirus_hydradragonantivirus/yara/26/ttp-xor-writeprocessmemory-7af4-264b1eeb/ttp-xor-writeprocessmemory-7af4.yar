rule TTP_XOR_WriteProcessMemory_7af4 {
  strings:
    $key_7af4 = { 2d 86 [2] 1f a4 [2] 19 91 [2] 37 91 [2] 08 8d }

  condition:
    any of them
}