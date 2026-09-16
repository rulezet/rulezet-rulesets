rule TTP_XOR_WriteProcessMemory_0706 {
  strings:
    $key_0706 = { 50 74 [2] 62 56 [2] 64 63 [2] 4a 63 [2] 75 7f }

  condition:
    any of them
}