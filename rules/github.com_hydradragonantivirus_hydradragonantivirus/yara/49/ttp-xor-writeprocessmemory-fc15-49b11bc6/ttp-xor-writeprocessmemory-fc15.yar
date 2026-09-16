rule TTP_XOR_WriteProcessMemory_fc15 {
  strings:
    $key_fc15 = { ab 67 [2] 99 45 [2] 9f 70 [2] b1 70 [2] 8e 6c }

  condition:
    any of them
}