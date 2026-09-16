rule TTP_XOR_WriteProcessMemory_fbbc {
  strings:
    $key_fbbc = { ac ce [2] 9e ec [2] 98 d9 [2] b6 d9 [2] 89 c5 }

  condition:
    any of them
}