rule TTP_XOR_WriteProcessMemory_2437 {
  strings:
    $key_2437 = { 73 45 [2] 41 67 [2] 47 52 [2] 69 52 [2] 56 4e }

  condition:
    any of them
}