rule TTP_XOR_WriteProcessMemory_308e {
  strings:
    $key_308e = { 67 fc [2] 55 de [2] 53 eb [2] 7d eb [2] 42 f7 }

  condition:
    any of them
}