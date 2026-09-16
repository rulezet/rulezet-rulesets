rule TTP_XOR_WriteProcessMemory_fc30 {
  strings:
    $key_fc30 = { ab 42 [2] 99 60 [2] 9f 55 [2] b1 55 [2] 8e 49 }

  condition:
    any of them
}