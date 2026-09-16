rule TTP_XOR_WriteProcessMemory_83fe {
  strings:
    $key_83fe = { d4 8c [2] e6 ae [2] e0 9b [2] ce 9b [2] f1 87 }

  condition:
    any of them
}