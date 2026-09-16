rule TTP_XOR_WriteProcessMemory_fc78 {
  strings:
    $key_fc78 = { ab 0a [2] 99 28 [2] 9f 1d [2] b1 1d [2] 8e 01 }

  condition:
    any of them
}