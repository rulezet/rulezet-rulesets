rule TTP_XOR_WriteProcessMemory_5dfe {
  strings:
    $key_5dfe = { 0a 8c [2] 38 ae [2] 3e 9b [2] 10 9b [2] 2f 87 }

  condition:
    any of them
}