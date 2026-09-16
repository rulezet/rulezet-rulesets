rule TTP_XOR_WriteProcessMemory_d0b5 {
  strings:
    $key_d0b5 = { 87 c7 [2] b5 e5 [2] b3 d0 [2] 9d d0 [2] a2 cc }

  condition:
    any of them
}