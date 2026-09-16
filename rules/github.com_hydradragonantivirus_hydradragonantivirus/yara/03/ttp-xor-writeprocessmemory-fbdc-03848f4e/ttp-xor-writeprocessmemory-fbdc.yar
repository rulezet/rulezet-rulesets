rule TTP_XOR_WriteProcessMemory_fbdc {
  strings:
    $key_fbdc = { ac ae [2] 9e 8c [2] 98 b9 [2] b6 b9 [2] 89 a5 }

  condition:
    any of them
}