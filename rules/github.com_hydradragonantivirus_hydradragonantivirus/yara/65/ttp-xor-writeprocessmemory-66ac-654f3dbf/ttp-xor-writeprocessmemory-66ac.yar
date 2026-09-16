rule TTP_XOR_WriteProcessMemory_66ac {
  strings:
    $key_66ac = { 31 de [2] 03 fc [2] 05 c9 [2] 2b c9 [2] 14 d5 }

  condition:
    any of them
}