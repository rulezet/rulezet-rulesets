rule TTP_XOR_WriteProcessMemory_fc28 {
  strings:
    $key_fc28 = { ab 5a [2] 99 78 [2] 9f 4d [2] b1 4d [2] 8e 51 }

  condition:
    any of them
}