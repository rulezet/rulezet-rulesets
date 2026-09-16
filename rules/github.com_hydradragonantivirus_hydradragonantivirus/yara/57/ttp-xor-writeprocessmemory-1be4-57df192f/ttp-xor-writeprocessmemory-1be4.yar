rule TTP_XOR_WriteProcessMemory_1be4 {
  strings:
    $key_1be4 = { 4c 96 [2] 7e b4 [2] 78 81 [2] 56 81 [2] 69 9d }

  condition:
    any of them
}