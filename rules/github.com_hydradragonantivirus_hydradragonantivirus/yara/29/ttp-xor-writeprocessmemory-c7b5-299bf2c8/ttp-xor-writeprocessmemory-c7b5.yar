rule TTP_XOR_WriteProcessMemory_c7b5 {
  strings:
    $key_c7b5 = { 90 c7 [2] a2 e5 [2] a4 d0 [2] 8a d0 [2] b5 cc }

  condition:
    any of them
}