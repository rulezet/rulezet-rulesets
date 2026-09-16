rule TTP_XOR_WriteProcessMemory_1dfe {
  strings:
    $key_1dfe = { 4a 8c [2] 78 ae [2] 7e 9b [2] 50 9b [2] 6f 87 }

  condition:
    any of them
}