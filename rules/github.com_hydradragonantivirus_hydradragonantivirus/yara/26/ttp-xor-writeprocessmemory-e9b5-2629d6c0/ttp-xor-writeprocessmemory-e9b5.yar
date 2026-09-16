rule TTP_XOR_WriteProcessMemory_e9b5 {
  strings:
    $key_e9b5 = { be c7 [2] 8c e5 [2] 8a d0 [2] a4 d0 [2] 9b cc }

  condition:
    any of them
}