rule TTP_XOR_WriteProcessMemory_e18e {
  strings:
    $key_e18e = { b6 fc [2] 84 de [2] 82 eb [2] ac eb [2] 93 f7 }

  condition:
    any of them
}