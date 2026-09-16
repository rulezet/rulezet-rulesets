rule TTP_XOR_WriteProcessMemory_08b3 {
  strings:
    $key_08b3 = { 5f c1 [2] 6d e3 [2] 6b d6 [2] 45 d6 [2] 7a ca }

  condition:
    any of them
}