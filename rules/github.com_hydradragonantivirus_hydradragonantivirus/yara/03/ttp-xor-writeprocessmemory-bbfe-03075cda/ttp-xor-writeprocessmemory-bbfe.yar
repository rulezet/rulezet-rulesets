rule TTP_XOR_WriteProcessMemory_bbfe {
  strings:
    $key_bbfe = { ec 8c [2] de ae [2] d8 9b [2] f6 9b [2] c9 87 }

  condition:
    any of them
}