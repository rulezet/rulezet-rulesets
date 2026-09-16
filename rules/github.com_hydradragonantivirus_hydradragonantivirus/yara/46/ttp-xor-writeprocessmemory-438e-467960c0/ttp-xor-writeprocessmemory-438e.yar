rule TTP_XOR_WriteProcessMemory_438e {
  strings:
    $key_438e = { 14 fc [2] 26 de [2] 20 eb [2] 0e eb [2] 31 f7 }

  condition:
    any of them
}