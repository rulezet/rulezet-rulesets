rule TTP_XOR_WriteProcessMemory_6dfe {
  strings:
    $key_6dfe = { 3a 8c [2] 08 ae [2] 0e 9b [2] 20 9b [2] 1f 87 }

  condition:
    any of them
}