rule TTP_XOR_WriteProcessMemory_fbe6 {
  strings:
    $key_fbe6 = { ac 94 [2] 9e b6 [2] 98 83 [2] b6 83 [2] 89 9f }

  condition:
    any of them
}