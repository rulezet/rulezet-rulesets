rule TTP_XOR_WriteProcessMemory_84fe {
  strings:
    $key_84fe = { d3 8c [2] e1 ae [2] e7 9b [2] c9 9b [2] f6 87 }

  condition:
    any of them
}