rule TTP_XOR_WriteProcessMemory_b2fe {
  strings:
    $key_b2fe = { e5 8c [2] d7 ae [2] d1 9b [2] ff 9b [2] c0 87 }

  condition:
    any of them
}