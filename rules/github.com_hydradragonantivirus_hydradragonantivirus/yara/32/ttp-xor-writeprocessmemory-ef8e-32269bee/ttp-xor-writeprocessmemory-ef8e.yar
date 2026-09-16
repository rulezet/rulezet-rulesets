rule TTP_XOR_WriteProcessMemory_ef8e {
  strings:
    $key_ef8e = { b8 fc [2] 8a de [2] 8c eb [2] a2 eb [2] 9d f7 }

  condition:
    any of them
}