rule TTP_XOR_WriteProcessMemory_bbec {
  strings:
    $key_bbec = { ec 9e [2] de bc [2] d8 89 [2] f6 89 [2] c9 95 }

  condition:
    any of them
}