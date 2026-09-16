rule TTP_XOR_WriteProcessMemory_1f8e {
  strings:
    $key_1f8e = { 48 fc [2] 7a de [2] 7c eb [2] 52 eb [2] 6d f7 }

  condition:
    any of them
}