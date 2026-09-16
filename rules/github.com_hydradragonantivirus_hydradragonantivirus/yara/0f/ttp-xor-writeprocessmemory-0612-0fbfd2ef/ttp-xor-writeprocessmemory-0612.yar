rule TTP_XOR_WriteProcessMemory_0612 {
  strings:
    $key_0612 = { 51 60 [2] 63 42 [2] 65 77 [2] 4b 77 [2] 74 6b }

  condition:
    any of them
}