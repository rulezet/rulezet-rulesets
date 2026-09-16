rule TTP_XOR_WriteProcessMemory_08b5 {
  strings:
    $key_08b5 = { 5f c7 [2] 6d e5 [2] 6b d0 [2] 45 d0 [2] 7a cc }

  condition:
    any of them
}