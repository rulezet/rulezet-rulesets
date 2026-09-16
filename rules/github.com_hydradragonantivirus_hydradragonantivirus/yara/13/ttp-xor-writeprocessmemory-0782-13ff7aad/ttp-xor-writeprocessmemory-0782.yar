rule TTP_XOR_WriteProcessMemory_0782 {
  strings:
    $key_0782 = { 50 f0 [2] 62 d2 [2] 64 e7 [2] 4a e7 [2] 75 fb }

  condition:
    any of them
}