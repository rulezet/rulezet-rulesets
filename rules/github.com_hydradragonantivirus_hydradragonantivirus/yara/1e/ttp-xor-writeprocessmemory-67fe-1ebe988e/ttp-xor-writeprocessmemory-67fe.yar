rule TTP_XOR_WriteProcessMemory_67fe {
  strings:
    $key_67fe = { 30 8c [2] 02 ae [2] 04 9b [2] 2a 9b [2] 15 87 }

  condition:
    any of them
}