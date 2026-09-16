rule TTP_XOR_WriteProcessMemory_fc38 {
  strings:
    $key_fc38 = { ab 4a [2] 99 68 [2] 9f 5d [2] b1 5d [2] 8e 41 }

  condition:
    any of them
}