rule TTP_XOR_WriteProcessMemory_16fe {
  strings:
    $key_16fe = { 41 8c [2] 73 ae [2] 75 9b [2] 5b 9b [2] 64 87 }

  condition:
    any of them
}