rule TTP_XOR_WriteProcessMemory_2a8e {
  strings:
    $key_2a8e = { 7d fc [2] 4f de [2] 49 eb [2] 67 eb [2] 58 f7 }

  condition:
    any of them
}