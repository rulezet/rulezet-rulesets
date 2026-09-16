rule TTP_XOR_WriteProcessMemory_fbfe {
  strings:
    $key_fbfe = { ac 8c [2] 9e ae [2] 98 9b [2] b6 9b [2] 89 87 }

  condition:
    any of them
}