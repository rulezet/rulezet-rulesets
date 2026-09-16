rule TTP_XOR_WriteProcessMemory_4af4 {
  strings:
    $key_4af4 = { 1d 86 [2] 2f a4 [2] 29 91 [2] 07 91 [2] 38 8d }

  condition:
    any of them
}