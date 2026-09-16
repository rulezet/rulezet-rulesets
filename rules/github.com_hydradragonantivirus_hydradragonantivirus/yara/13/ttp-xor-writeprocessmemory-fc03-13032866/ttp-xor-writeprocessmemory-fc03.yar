rule TTP_XOR_WriteProcessMemory_fc03 {
  strings:
    $key_fc03 = { ab 71 [2] 99 53 [2] 9f 66 [2] b1 66 [2] 8e 7a }

  condition:
    any of them
}