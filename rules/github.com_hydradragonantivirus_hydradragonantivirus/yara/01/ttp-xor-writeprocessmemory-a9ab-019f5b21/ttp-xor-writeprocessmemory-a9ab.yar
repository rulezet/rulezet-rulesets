rule TTP_XOR_WriteProcessMemory_a9ab {
  strings:
    $key_a9ab = { fe d9 [2] cc fb [2] ca ce [2] e4 ce [2] db d2 }

  condition:
    any of them
}