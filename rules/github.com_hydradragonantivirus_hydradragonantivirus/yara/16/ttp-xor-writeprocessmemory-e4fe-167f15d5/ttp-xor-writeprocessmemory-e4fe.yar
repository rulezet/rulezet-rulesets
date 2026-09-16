rule TTP_XOR_WriteProcessMemory_e4fe {
  strings:
    $key_e4fe = { b3 8c [2] 81 ae [2] 87 9b [2] a9 9b [2] 96 87 }

  condition:
    any of them
}