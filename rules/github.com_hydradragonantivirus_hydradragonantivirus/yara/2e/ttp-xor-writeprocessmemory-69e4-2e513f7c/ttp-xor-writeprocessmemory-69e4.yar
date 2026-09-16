rule TTP_XOR_WriteProcessMemory_69e4 {
  strings:
    $key_69e4 = { 3e 96 [2] 0c b4 [2] 0a 81 [2] 24 81 [2] 1b 9d }

  condition:
    any of them
}