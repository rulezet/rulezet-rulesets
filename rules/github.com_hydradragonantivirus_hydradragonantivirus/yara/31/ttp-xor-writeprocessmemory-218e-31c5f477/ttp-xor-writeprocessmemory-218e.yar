rule TTP_XOR_WriteProcessMemory_218e {
  strings:
    $key_218e = { 76 fc [2] 44 de [2] 42 eb [2] 6c eb [2] 53 f7 }

  condition:
    any of them
}