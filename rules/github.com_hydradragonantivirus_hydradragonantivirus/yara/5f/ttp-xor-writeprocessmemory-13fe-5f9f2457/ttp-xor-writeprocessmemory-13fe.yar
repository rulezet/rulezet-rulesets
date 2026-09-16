rule TTP_XOR_WriteProcessMemory_13fe {
  strings:
    $key_13fe = { 44 8c [2] 76 ae [2] 70 9b [2] 5e 9b [2] 61 87 }

  condition:
    any of them
}