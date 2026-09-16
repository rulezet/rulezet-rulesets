rule TTP_XOR_WriteProcessMemory_bdcc {
  strings:
    $key_bdcc = { ea be [2] d8 9c [2] de a9 [2] f0 a9 [2] cf b5 }

  condition:
    any of them
}