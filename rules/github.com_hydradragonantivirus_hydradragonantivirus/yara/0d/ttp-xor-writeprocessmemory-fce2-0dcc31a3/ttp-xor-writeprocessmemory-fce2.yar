rule TTP_XOR_WriteProcessMemory_fce2 {
  strings:
    $key_fce2 = { ab 90 [2] 99 b2 [2] 9f 87 [2] b1 87 [2] 8e 9b }

  condition:
    any of them
}