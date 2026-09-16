rule TTP_XOR_WriteProcessMemory_3cf6 {
  strings:
    $key_3cf6 = { 6b 84 [2] 59 a6 [2] 5f 93 [2] 71 93 [2] 4e 8f }

  condition:
    any of them
}