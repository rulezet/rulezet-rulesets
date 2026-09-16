rule TTP_XOR_WriteProcessMemory_3031 {
  strings:
    $key_3031 = { 67 43 [2] 55 61 [2] 53 54 [2] 7d 54 [2] 42 48 }

  condition:
    any of them
}