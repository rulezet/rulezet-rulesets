rule TTP_XOR_WriteProcessMemory_3a8e {
  strings:
    $key_3a8e = { 6d fc [2] 5f de [2] 59 eb [2] 77 eb [2] 48 f7 }

  condition:
    any of them
}