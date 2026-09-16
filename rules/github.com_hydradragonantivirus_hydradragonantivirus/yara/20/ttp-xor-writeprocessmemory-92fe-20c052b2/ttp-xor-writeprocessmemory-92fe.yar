rule TTP_XOR_WriteProcessMemory_92fe {
  strings:
    $key_92fe = { c5 8c [2] f7 ae [2] f1 9b [2] df 9b [2] e0 87 }

  condition:
    any of them
}