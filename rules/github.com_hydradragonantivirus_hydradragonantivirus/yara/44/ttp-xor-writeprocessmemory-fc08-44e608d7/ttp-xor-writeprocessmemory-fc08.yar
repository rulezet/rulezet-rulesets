rule TTP_XOR_WriteProcessMemory_fc08 {
  strings:
    $key_fc08 = { ab 7a [2] 99 58 [2] 9f 6d [2] b1 6d [2] 8e 71 }

  condition:
    any of them
}