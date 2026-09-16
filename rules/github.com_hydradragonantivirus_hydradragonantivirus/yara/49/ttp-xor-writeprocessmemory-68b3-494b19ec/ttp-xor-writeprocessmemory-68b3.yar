rule TTP_XOR_WriteProcessMemory_68b3 {
  strings:
    $key_68b3 = { 3f c1 [2] 0d e3 [2] 0b d6 [2] 25 d6 [2] 1a ca }

  condition:
    any of them
}