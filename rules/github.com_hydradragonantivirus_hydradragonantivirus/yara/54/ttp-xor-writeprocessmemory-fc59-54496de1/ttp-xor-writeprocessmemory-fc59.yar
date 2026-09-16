rule TTP_XOR_WriteProcessMemory_fc59 {
  strings:
    $key_fc59 = { ab 2b [2] 99 09 [2] 9f 3c [2] b1 3c [2] 8e 20 }

  condition:
    any of them
}