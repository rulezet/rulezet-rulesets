rule TTP_XOR_WriteProcessMemory_fc25 {
  strings:
    $key_fc25 = { ab 57 [2] 99 75 [2] 9f 40 [2] b1 40 [2] 8e 5c }

  condition:
    any of them
}