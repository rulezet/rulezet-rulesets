rule TTP_XOR_WriteProcessMemory_0df6 {
  strings:
    $key_0df6 = { 5a 84 [2] 68 a6 [2] 6e 93 [2] 40 93 [2] 7f 8f }

  condition:
    any of them
}