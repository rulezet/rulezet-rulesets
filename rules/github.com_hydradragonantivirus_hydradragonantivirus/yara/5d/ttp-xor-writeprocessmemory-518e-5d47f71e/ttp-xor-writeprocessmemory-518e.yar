rule TTP_XOR_WriteProcessMemory_518e {
  strings:
    $key_518e = { 06 fc [2] 34 de [2] 32 eb [2] 1c eb [2] 23 f7 }

  condition:
    any of them
}