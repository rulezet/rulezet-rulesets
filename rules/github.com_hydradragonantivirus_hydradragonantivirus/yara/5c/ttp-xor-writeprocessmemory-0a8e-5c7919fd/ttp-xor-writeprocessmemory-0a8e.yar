rule TTP_XOR_WriteProcessMemory_0a8e {
  strings:
    $key_0a8e = { 5d fc [2] 6f de [2] 69 eb [2] 47 eb [2] 78 f7 }

  condition:
    any of them
}