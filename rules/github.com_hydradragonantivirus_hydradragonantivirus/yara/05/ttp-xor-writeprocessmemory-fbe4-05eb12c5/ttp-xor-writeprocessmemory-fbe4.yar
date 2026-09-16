rule TTP_XOR_WriteProcessMemory_fbe4 {
  strings:
    $key_fbe4 = { ac 96 [2] 9e b4 [2] 98 81 [2] b6 81 [2] 89 9d }

  condition:
    any of them
}