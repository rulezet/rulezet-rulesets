rule TTP_XOR_WriteProcessMemory_25cb {
  strings:
    $key_25cb = { 72 b9 [2] 40 9b [2] 46 ae [2] 68 ae [2] 57 b2 }

  condition:
    any of them
}