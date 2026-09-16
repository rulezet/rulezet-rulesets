rule TTP_XOR_WriteProcessMemory_fbf9 {
  strings:
    $key_fbf9 = { ac 8b [2] 9e a9 [2] 98 9c [2] b6 9c [2] 89 80 }

  condition:
    any of them
}