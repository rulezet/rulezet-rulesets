rule TTP_XOR_WriteProcessMemory_50b5 {
  strings:
    $key_50b5 = { 07 c7 [2] 35 e5 [2] 33 d0 [2] 1d d0 [2] 22 cc }

  condition:
    any of them
}