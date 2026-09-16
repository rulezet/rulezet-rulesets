rule TTP_XOR_WriteProcessMemory_26fe {
  strings:
    $key_26fe = { 71 8c [2] 43 ae [2] 45 9b [2] 6b 9b [2] 54 87 }

  condition:
    any of them
}