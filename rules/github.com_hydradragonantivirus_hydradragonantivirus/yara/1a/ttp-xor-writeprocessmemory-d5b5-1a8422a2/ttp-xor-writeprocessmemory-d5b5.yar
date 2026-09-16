rule TTP_XOR_WriteProcessMemory_d5b5 {
  strings:
    $key_d5b5 = { 82 c7 [2] b0 e5 [2] b6 d0 [2] 98 d0 [2] a7 cc }

  condition:
    any of them
}