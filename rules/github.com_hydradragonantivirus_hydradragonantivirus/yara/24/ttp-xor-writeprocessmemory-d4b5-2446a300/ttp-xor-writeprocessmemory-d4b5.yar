rule TTP_XOR_WriteProcessMemory_d4b5 {
  strings:
    $key_d4b5 = { 83 c7 [2] b1 e5 [2] b7 d0 [2] 99 d0 [2] a6 cc }

  condition:
    any of them
}