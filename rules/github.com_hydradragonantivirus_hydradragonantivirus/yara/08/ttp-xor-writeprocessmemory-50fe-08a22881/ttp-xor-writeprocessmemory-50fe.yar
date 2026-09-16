rule TTP_XOR_WriteProcessMemory_50fe {
  strings:
    $key_50fe = { 07 8c [2] 35 ae [2] 33 9b [2] 1d 9b [2] 22 87 }

  condition:
    any of them
}