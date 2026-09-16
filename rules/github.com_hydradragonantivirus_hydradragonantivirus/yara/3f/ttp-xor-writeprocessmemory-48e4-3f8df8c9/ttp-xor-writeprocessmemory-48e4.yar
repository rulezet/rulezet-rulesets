rule TTP_XOR_WriteProcessMemory_48e4 {
  strings:
    $key_48e4 = { 1f 96 [2] 2d b4 [2] 2b 81 [2] 05 81 [2] 3a 9d }

  condition:
    any of them
}