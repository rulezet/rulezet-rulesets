rule TTP_XOR_WriteProcessMemory_feef {
  strings:
    $key_feef = { a9 9d [2] 9b bf [2] 9d 8a [2] b3 8a [2] 8c 96 }

  condition:
    any of them
}