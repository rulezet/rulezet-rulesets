rule TTP_XOR_WriteProcessMemory_fbac {
  strings:
    $key_fbac = { ac de [2] 9e fc [2] 98 c9 [2] b6 c9 [2] 89 d5 }

  condition:
    any of them
}