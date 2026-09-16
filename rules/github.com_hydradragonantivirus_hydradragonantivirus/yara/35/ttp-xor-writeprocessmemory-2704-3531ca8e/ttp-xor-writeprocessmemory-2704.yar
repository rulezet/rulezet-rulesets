rule TTP_XOR_WriteProcessMemory_2704 {
  strings:
    $key_2704 = { 70 76 [2] 42 54 [2] 44 61 [2] 6a 61 [2] 55 7d }

  condition:
    any of them
}