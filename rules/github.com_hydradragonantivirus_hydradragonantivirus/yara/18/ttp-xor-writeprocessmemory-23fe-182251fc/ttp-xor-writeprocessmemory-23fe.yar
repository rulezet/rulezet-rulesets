rule TTP_XOR_WriteProcessMemory_23fe {
  strings:
    $key_23fe = { 74 8c [2] 46 ae [2] 40 9b [2] 6e 9b [2] 51 87 }

  condition:
    any of them
}