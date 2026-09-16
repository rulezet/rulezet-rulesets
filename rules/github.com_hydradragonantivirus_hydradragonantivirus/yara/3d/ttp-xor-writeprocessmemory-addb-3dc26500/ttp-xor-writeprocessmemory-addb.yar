rule TTP_XOR_WriteProcessMemory_addb {
  strings:
    $key_addb = { fa a9 [2] c8 8b [2] ce be [2] e0 be [2] df a2 }

  condition:
    any of them
}