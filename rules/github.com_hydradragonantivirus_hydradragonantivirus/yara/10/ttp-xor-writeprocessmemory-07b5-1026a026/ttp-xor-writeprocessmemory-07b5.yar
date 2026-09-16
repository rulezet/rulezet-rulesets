rule TTP_XOR_WriteProcessMemory_07b5 {
  strings:
    $key_07b5 = { 50 c7 [2] 62 e5 [2] 64 d0 [2] 4a d0 [2] 75 cc }

  condition:
    any of them
}