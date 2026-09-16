rule TTP_XOR_WriteProcessMemory_4dfe {
  strings:
    $key_4dfe = { 1a 8c [2] 28 ae [2] 2e 9b [2] 00 9b [2] 3f 87 }

  condition:
    any of them
}