rule TTP_XOR_WriteProcessMemory_47fe {
  strings:
    $key_47fe = { 10 8c [2] 22 ae [2] 24 9b [2] 0a 9b [2] 35 87 }

  condition:
    any of them
}