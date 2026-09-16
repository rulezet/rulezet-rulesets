rule TTP_XOR_WriteProcessMemory_64b5 {
  strings:
    $key_64b5 = { 33 c7 [2] 01 e5 [2] 07 d0 [2] 29 d0 [2] 16 cc }

  condition:
    any of them
}