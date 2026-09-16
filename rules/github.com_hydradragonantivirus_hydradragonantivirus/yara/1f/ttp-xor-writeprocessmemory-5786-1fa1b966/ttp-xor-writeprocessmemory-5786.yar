rule TTP_XOR_WriteProcessMemory_5786 {
  strings:
    $key_5786 = { 00 f4 [2] 32 d6 [2] 34 e3 [2] 1a e3 [2] 25 ff }

  condition:
    any of them
}