rule TTP_XOR_WriteProcessMemory_e9b3 {
  strings:
    $key_e9b3 = { be c1 [2] 8c e3 [2] 8a d6 [2] a4 d6 [2] 9b ca }

  condition:
    any of them
}