rule TTP_XOR_WriteProcessMemory_fbe2 {
  strings:
    $key_fbe2 = { ac 90 [2] 9e b2 [2] 98 87 [2] b6 87 [2] 89 9b }

  condition:
    any of them
}