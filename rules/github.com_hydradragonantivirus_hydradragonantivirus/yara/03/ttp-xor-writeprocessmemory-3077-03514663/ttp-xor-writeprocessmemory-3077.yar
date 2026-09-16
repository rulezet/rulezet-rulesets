rule TTP_XOR_WriteProcessMemory_3077 {
  strings:
    $key_3077 = { 67 05 [2] 55 27 [2] 53 12 [2] 7d 12 [2] 42 0e }

  condition:
    any of them
}