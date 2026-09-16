rule TTP_XOR_WriteProcessMemory_fc4c {
  strings:
    $key_fc4c = { ab 3e [2] 99 1c [2] 9f 29 [2] b1 29 [2] 8e 35 }

  condition:
    any of them
}