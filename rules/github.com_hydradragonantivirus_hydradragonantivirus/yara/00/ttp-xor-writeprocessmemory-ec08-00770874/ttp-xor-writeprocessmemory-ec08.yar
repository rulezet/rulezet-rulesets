rule TTP_XOR_WriteProcessMemory_ec08 {
  strings:
    $key_ec08 = { bb 7a [2] 89 58 [2] 8f 6d [2] a1 6d [2] 9e 71 }

  condition:
    any of them
}