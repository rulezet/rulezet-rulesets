rule TTP_XOR_WriteProcessMemory_e9e4 {
  strings:
    $key_e9e4 = { be 96 [2] 8c b4 [2] 8a 81 [2] a4 81 [2] 9b 9d }

  condition:
    any of them
}