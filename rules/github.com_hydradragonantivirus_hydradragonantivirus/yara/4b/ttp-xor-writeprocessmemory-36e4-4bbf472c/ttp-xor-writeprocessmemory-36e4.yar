rule TTP_XOR_WriteProcessMemory_36e4 {
  strings:
    $key_36e4 = { 61 96 [2] 53 b4 [2] 55 81 [2] 7b 81 [2] 44 9d }

  condition:
    any of them
}