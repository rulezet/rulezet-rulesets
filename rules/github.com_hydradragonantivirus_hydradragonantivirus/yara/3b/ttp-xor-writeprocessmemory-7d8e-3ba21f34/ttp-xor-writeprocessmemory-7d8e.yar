rule TTP_XOR_WriteProcessMemory_7d8e {
  strings:
    $key_7d8e = { 2a fc [2] 18 de [2] 1e eb [2] 30 eb [2] 0f f7 }

  condition:
    any of them
}