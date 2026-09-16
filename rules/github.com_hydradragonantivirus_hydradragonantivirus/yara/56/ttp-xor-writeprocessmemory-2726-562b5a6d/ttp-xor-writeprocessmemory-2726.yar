rule TTP_XOR_WriteProcessMemory_2726 {
  strings:
    $key_2726 = { 70 54 [2] 42 76 [2] 44 43 [2] 6a 43 [2] 55 5f }

  condition:
    any of them
}