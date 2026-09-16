rule TTP_XOR_WriteProcessMemory_fc52 {
  strings:
    $key_fc52 = { ab 20 [2] 99 02 [2] 9f 37 [2] b1 37 [2] 8e 2b }

  condition:
    any of them
}