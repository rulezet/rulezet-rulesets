rule TTP_XOR_WriteProcessMemory_fc2e {
  strings:
    $key_fc2e = { ab 5c [2] 99 7e [2] 9f 4b [2] b1 4b [2] 8e 57 }

  condition:
    any of them
}