rule TTP_XOR_WriteProcessMemory_9e8e {
  strings:
    $key_9e8e = { c9 fc [2] fb de [2] fd eb [2] d3 eb [2] ec f7 }

  condition:
    any of them
}