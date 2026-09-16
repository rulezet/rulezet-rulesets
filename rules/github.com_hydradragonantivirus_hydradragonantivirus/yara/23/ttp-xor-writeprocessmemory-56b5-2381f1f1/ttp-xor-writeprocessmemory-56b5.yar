rule TTP_XOR_WriteProcessMemory_56b5 {
  strings:
    $key_56b5 = { 01 c7 [2] 33 e5 [2] 35 d0 [2] 1b d0 [2] 24 cc }

  condition:
    any of them
}