rule TTP_XOR_WriteProcessMemory_3004 {
  strings:
    $key_3004 = { 67 76 [2] 55 54 [2] 53 61 [2] 7d 61 [2] 42 7d }

  condition:
    any of them
}