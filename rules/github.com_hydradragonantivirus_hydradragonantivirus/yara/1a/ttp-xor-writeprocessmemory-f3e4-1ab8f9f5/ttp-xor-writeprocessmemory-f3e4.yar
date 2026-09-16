rule TTP_XOR_WriteProcessMemory_f3e4 {
  strings:
    $key_f3e4 = { a4 96 [2] 96 b4 [2] 90 81 [2] be 81 [2] 81 9d }

  condition:
    any of them
}