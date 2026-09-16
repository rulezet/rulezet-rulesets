rule TTP_XOR_WriteProcessMemory_038e {
  strings:
    $key_038e = { 54 fc [2] 66 de [2] 60 eb [2] 4e eb [2] 71 f7 }

  condition:
    any of them
}