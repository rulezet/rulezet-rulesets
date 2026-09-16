rule TTP_XOR_WriteProcessMemory_fbea {
  strings:
    $key_fbea = { ac 98 [2] 9e ba [2] 98 8f [2] b6 8f [2] 89 93 }

  condition:
    any of them
}