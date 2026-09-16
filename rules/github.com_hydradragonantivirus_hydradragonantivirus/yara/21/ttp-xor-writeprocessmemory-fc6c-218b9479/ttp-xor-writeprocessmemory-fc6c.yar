rule TTP_XOR_WriteProcessMemory_fc6c {
  strings:
    $key_fc6c = { ab 1e [2] 99 3c [2] 9f 09 [2] b1 09 [2] 8e 15 }

  condition:
    any of them
}