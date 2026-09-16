rule TTP_XOR_WriteProcessMemory_f5b5 {
  strings:
    $key_f5b5 = { a2 c7 [2] 90 e5 [2] 96 d0 [2] b8 d0 [2] 87 cc }

  condition:
    any of them
}