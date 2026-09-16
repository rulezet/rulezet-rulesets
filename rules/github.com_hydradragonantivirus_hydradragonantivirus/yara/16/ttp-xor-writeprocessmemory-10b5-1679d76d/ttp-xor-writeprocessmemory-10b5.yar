rule TTP_XOR_WriteProcessMemory_10b5 {
  strings:
    $key_10b5 = { 47 c7 [2] 75 e5 [2] 73 d0 [2] 5d d0 [2] 62 cc }

  condition:
    any of them
}