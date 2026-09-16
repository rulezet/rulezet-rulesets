rule TTP_XOR_WriteProcessMemory_a6fe {
  strings:
    $key_a6fe = { f1 8c [2] c3 ae [2] c5 9b [2] eb 9b [2] d4 87 }

  condition:
    any of them
}