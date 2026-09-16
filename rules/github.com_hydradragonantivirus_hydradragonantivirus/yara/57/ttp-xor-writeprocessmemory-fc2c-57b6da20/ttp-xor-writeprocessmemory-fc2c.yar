rule TTP_XOR_WriteProcessMemory_fc2c {
  strings:
    $key_fc2c = { ab 5e [2] 99 7c [2] 9f 49 [2] b1 49 [2] 8e 55 }

  condition:
    any of them
}