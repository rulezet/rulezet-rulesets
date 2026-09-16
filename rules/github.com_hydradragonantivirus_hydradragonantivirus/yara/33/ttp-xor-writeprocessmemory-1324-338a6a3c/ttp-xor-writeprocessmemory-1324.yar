rule TTP_XOR_WriteProcessMemory_1324 {
  strings:
    $key_1324 = { 44 56 [2] 76 74 [2] 70 41 [2] 5e 41 [2] 61 5d }

  condition:
    any of them
}