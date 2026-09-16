rule TTP_XOR_WriteProcessMemory_21e4 {
  strings:
    $key_21e4 = { 76 96 [2] 44 b4 [2] 42 81 [2] 6c 81 [2] 53 9d }

  condition:
    any of them
}