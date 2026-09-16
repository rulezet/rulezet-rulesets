rule TTP_XOR_WriteProcessMemory_96fe {
  strings:
    $key_96fe = { c1 8c [2] f3 ae [2] f5 9b [2] db 9b [2] e4 87 }

  condition:
    any of them
}