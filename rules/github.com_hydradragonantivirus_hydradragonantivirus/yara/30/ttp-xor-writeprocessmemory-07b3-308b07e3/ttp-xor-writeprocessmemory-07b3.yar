rule TTP_XOR_WriteProcessMemory_07b3 {
  strings:
    $key_07b3 = { 50 c1 [2] 62 e3 [2] 64 d6 [2] 4a d6 [2] 75 ca }

  condition:
    any of them
}