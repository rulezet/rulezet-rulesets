rule TTP_XOR_WriteProcessMemory_fc3c {
  strings:
    $key_fc3c = { ab 4e [2] 99 6c [2] 9f 59 [2] b1 59 [2] 8e 45 }

  condition:
    any of them
}