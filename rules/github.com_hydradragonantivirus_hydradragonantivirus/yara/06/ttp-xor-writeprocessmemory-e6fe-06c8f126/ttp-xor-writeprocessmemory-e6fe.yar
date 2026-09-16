rule TTP_XOR_WriteProcessMemory_e6fe {
  strings:
    $key_e6fe = { b1 8c [2] 83 ae [2] 85 9b [2] ab 9b [2] 94 87 }

  condition:
    any of them
}