rule TTP_XOR_WriteProcessMemory_0721 {
  strings:
    $key_0721 = { 50 53 [2] 62 71 [2] 64 44 [2] 4a 44 [2] 75 58 }

  condition:
    any of them
}