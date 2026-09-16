rule TTP_XOR_WriteProcessMemory_74b5 {
  strings:
    $key_74b5 = { 23 c7 [2] 11 e5 [2] 17 d0 [2] 39 d0 [2] 06 cc }

  condition:
    any of them
}