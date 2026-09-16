rule TTP_XOR_WriteProcessMemory_0d8e {
  strings:
    $key_0d8e = { 5a fc [2] 68 de [2] 6e eb [2] 40 eb [2] 7f f7 }

  condition:
    any of them
}