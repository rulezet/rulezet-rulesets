rule TTP_XOR_WriteProcessMemory_51fe {
  strings:
    $key_51fe = { 06 8c [2] 34 ae [2] 32 9b [2] 1c 9b [2] 23 87 }

  condition:
    any of them
}