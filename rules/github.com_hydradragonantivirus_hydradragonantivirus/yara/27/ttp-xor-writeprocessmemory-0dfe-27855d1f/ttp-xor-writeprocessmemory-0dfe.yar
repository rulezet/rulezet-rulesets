rule TTP_XOR_WriteProcessMemory_0dfe {
  strings:
    $key_0dfe = { 5a 8c [2] 68 ae [2] 6e 9b [2] 40 9b [2] 7f 87 }

  condition:
    any of them
}