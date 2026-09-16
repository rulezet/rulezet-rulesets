rule TTP_XOR_WriteProcessMemory_7524 {
  strings:
    $key_7524 = { 22 56 [2] 10 74 [2] 16 41 [2] 38 41 [2] 07 5d }

  condition:
    any of them
}