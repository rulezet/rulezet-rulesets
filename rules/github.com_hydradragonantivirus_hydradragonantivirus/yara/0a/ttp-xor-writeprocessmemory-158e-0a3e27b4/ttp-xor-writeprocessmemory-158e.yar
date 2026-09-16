rule TTP_XOR_WriteProcessMemory_158e {
  strings:
    $key_158e = { 42 fc [2] 70 de [2] 76 eb [2] 58 eb [2] 67 f7 }

  condition:
    any of them
}