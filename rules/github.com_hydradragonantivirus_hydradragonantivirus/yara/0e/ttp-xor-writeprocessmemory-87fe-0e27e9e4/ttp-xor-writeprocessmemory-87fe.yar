rule TTP_XOR_WriteProcessMemory_87fe {
  strings:
    $key_87fe = { d0 8c [2] e2 ae [2] e4 9b [2] ca 9b [2] f5 87 }

  condition:
    any of them
}