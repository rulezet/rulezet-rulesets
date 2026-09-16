rule TTP_XOR_WriteProcessMemory_90fe {
  strings:
    $key_90fe = { c7 8c [2] f5 ae [2] f3 9b [2] dd 9b [2] e2 87 }

  condition:
    any of them
}