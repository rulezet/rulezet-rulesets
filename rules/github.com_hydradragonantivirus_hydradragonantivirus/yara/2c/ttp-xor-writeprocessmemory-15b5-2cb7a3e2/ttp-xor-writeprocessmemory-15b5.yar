rule TTP_XOR_WriteProcessMemory_15b5 {
  strings:
    $key_15b5 = { 42 c7 [2] 70 e5 [2] 76 d0 [2] 58 d0 [2] 67 cc }

  condition:
    any of them
}