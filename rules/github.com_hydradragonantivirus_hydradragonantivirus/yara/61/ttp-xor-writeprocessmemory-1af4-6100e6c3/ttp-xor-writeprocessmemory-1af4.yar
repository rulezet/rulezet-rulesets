rule TTP_XOR_WriteProcessMemory_1af4 {
  strings:
    $key_1af4 = { 4d 86 [2] 7f a4 [2] 79 91 [2] 57 91 [2] 68 8d }

  condition:
    any of them
}