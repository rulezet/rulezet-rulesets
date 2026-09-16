rule TTP_XOR_WriteProcessMemory_fc18 {
  strings:
    $key_fc18 = { ab 6a [2] 99 48 [2] 9f 7d [2] b1 7d [2] 8e 61 }

  condition:
    any of them
}