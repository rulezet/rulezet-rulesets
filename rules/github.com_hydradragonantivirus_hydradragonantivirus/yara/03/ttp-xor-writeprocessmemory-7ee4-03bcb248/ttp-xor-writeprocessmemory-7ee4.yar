rule TTP_XOR_WriteProcessMemory_7ee4 {
  strings:
    $key_7ee4 = { 29 96 [2] 1b b4 [2] 1d 81 [2] 33 81 [2] 0c 9d }

  condition:
    any of them
}