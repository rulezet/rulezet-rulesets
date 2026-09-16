rule TTP_XOR_WriteProcessMemory_1a8e {
  strings:
    $key_1a8e = { 4d fc [2] 7f de [2] 79 eb [2] 57 eb [2] 68 f7 }

  condition:
    any of them
}