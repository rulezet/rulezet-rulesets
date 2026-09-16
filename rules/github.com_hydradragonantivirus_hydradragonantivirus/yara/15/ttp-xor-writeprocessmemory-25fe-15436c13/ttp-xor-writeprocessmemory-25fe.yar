rule TTP_XOR_WriteProcessMemory_25fe {
  strings:
    $key_25fe = { 72 8c [2] 40 ae [2] 46 9b [2] 68 9b [2] 57 87 }

  condition:
    any of them
}