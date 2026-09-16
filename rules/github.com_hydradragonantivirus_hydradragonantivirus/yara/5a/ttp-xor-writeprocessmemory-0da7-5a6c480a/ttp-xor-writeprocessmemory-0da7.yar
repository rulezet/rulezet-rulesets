rule TTP_XOR_WriteProcessMemory_0da7 {
  strings:
    $key_0da7 = { 5a d5 [2] 68 f7 [2] 6e c2 [2] 40 c2 [2] 7f de }

  condition:
    any of them
}