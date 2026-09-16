rule TTP_XOR_WriteProcessMemory_30b5 {
  strings:
    $key_30b5 = { 67 c7 [2] 55 e5 [2] 53 d0 [2] 7d d0 [2] 42 cc }

  condition:
    any of them
}