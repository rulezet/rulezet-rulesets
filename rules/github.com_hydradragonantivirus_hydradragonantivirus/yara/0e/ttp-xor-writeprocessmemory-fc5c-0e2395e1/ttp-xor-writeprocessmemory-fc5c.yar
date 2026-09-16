rule TTP_XOR_WriteProcessMemory_fc5c {
  strings:
    $key_fc5c = { ab 2e [2] 99 0c [2] 9f 39 [2] b1 39 [2] 8e 25 }

  condition:
    any of them
}