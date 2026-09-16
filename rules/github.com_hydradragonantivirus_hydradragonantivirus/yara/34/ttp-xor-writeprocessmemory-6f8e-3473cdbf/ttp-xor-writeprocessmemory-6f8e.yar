rule TTP_XOR_WriteProcessMemory_6f8e {
  strings:
    $key_6f8e = { 38 fc [2] 0a de [2] 0c eb [2] 22 eb [2] 1d f7 }

  condition:
    any of them
}