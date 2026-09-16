rule TTP_XOR_WriteProcessMemory_628e {
  strings:
    $key_628e = { 35 fc [2] 07 de [2] 01 eb [2] 2f eb [2] 10 f7 }

  condition:
    any of them
}