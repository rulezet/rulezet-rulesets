rule TTP_XOR_WriteProcessMemory_fbf2 {
  strings:
    $key_fbf2 = { ac 80 [2] 9e a2 [2] 98 97 [2] b6 97 [2] 89 8b }

  condition:
    any of them
}