rule TTP_XOR_WriteProcessMemory_7be4 {
  strings:
    $key_7be4 = { 2c 96 [2] 1e b4 [2] 18 81 [2] 36 81 [2] 09 9d }

  condition:
    any of them
}