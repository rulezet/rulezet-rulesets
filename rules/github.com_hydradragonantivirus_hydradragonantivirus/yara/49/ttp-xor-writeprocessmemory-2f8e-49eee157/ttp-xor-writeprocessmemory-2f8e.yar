rule TTP_XOR_WriteProcessMemory_2f8e {
  strings:
    $key_2f8e = { 78 fc [2] 4a de [2] 4c eb [2] 62 eb [2] 5d f7 }

  condition:
    any of them
}