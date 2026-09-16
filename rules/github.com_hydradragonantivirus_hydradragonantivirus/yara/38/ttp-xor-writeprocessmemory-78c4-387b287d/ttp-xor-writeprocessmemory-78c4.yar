rule TTP_XOR_WriteProcessMemory_78c4 {
  strings:
    $key_78c4 = { 2f b6 [2] 1d 94 [2] 1b a1 [2] 35 a1 [2] 0a bd }

  condition:
    any of them
}