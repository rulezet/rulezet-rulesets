rule TTP_XOR_WriteProcessMemory_68b5 {
  strings:
    $key_68b5 = { 3f c7 [2] 0d e5 [2] 0b d0 [2] 25 d0 [2] 1a cc }

  condition:
    any of them
}