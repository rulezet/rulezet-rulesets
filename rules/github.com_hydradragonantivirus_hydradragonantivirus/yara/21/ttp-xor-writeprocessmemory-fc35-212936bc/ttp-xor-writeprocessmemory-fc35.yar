rule TTP_XOR_WriteProcessMemory_fc35 {
  strings:
    $key_fc35 = { ab 47 [2] 99 65 [2] 9f 50 [2] b1 50 [2] 8e 4c }

  condition:
    any of them
}