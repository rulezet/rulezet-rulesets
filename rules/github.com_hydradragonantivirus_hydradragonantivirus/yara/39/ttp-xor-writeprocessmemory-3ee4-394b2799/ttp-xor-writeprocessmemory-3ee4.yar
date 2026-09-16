rule TTP_XOR_WriteProcessMemory_3ee4 {
  strings:
    $key_3ee4 = { 69 96 [2] 5b b4 [2] 5d 81 [2] 73 81 [2] 4c 9d }

  condition:
    any of them
}