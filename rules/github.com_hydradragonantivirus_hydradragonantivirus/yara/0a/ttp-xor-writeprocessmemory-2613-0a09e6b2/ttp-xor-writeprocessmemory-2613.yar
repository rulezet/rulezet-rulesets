rule TTP_XOR_WriteProcessMemory_2613 {
  strings:
    $key_2613 = { 71 61 [2] 43 43 [2] 45 76 [2] 6b 76 [2] 54 6a }

  condition:
    any of them
}