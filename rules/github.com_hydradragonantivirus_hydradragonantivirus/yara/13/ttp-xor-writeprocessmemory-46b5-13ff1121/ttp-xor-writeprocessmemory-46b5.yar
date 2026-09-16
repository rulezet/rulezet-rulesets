rule TTP_XOR_WriteProcessMemory_46b5 {
  strings:
    $key_46b5 = { 11 c7 [2] 23 e5 [2] 25 d0 [2] 0b d0 [2] 34 cc }

  condition:
    any of them
}