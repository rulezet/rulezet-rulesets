rule TTP_XOR_WriteProcessMemory_21fe {
  strings:
    $key_21fe = { 76 8c [2] 44 ae [2] 42 9b [2] 6c 9b [2] 53 87 }

  condition:
    any of them
}