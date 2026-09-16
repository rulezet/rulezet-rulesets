rule TTP_XOR_WriteProcessMemory_71fe {
  strings:
    $key_71fe = { 26 8c [2] 14 ae [2] 12 9b [2] 3c 9b [2] 03 87 }

  condition:
    any of them
}