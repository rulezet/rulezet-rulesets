rule TTP_XOR_WriteProcessMemory_2464 {
  strings:
    $key_2464 = { 73 16 [2] 41 34 [2] 47 01 [2] 69 01 [2] 56 1d }

  condition:
    any of them
}