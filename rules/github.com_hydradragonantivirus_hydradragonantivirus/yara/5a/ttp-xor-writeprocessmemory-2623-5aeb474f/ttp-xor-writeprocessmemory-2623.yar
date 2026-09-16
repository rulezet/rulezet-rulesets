rule TTP_XOR_WriteProcessMemory_2623 {
  strings:
    $key_2623 = { 71 51 [2] 43 73 [2] 45 46 [2] 6b 46 [2] 54 5a }

  condition:
    any of them
}