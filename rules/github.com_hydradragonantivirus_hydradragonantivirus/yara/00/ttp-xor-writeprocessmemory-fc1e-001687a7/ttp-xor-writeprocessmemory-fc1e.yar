rule TTP_XOR_WriteProcessMemory_fc1e {
  strings:
    $key_fc1e = { ab 6c [2] 99 4e [2] 9f 7b [2] b1 7b [2] 8e 67 }

  condition:
    any of them
}