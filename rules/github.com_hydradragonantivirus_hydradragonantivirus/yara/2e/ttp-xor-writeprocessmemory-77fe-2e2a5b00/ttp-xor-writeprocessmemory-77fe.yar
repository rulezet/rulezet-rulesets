rule TTP_XOR_WriteProcessMemory_77fe {
  strings:
    $key_77fe = { 20 8c [2] 12 ae [2] 14 9b [2] 3a 9b [2] 05 87 }

  condition:
    any of them
}