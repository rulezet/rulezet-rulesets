rule TTP_XOR_WriteProcessMemory_fc8e {
  strings:
    $key_fc8e = { ab fc [2] 99 de [2] 9f eb [2] b1 eb [2] 8e f7 }

  condition:
    any of them
}