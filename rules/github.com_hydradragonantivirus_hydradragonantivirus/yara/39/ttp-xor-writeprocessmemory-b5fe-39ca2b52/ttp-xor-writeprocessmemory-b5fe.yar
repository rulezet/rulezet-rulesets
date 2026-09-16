rule TTP_XOR_WriteProcessMemory_b5fe {
  strings:
    $key_b5fe = { e2 8c [2] d0 ae [2] d6 9b [2] f8 9b [2] c7 87 }

  condition:
    any of them
}