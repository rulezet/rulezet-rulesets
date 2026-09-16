rule TTP_XOR_WriteProcessMemory_fbf6 {
  strings:
    $key_fbf6 = { ac 84 [2] 9e a6 [2] 98 93 [2] b6 93 [2] 89 8f }

  condition:
    any of them
}