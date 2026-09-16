rule TTP_XOR_WriteProcessMemory_84ab {
  strings:
    $key_84ab = { d3 d9 [2] e1 fb [2] e7 ce [2] c9 ce [2] f6 d2 }

  condition:
    any of them
}