rule TTP_XOR_WriteProcessMemory_41fe {
  strings:
    $key_41fe = { 16 8c [2] 24 ae [2] 22 9b [2] 0c 9b [2] 33 87 }

  condition:
    any of them
}