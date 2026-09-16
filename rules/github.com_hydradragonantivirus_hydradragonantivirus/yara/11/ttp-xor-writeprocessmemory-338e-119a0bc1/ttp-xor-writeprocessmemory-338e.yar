rule TTP_XOR_WriteProcessMemory_338e {
  strings:
    $key_338e = { 64 fc [2] 56 de [2] 50 eb [2] 7e eb [2] 41 f7 }

  condition:
    any of them
}