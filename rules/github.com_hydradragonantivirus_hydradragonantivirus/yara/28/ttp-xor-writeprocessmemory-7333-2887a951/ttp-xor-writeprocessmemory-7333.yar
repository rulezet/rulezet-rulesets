rule TTP_XOR_WriteProcessMemory_7333 {
  strings:
    $key_7333 = { 24 41 [2] 16 63 [2] 10 56 [2] 3e 56 [2] 01 4a }

  condition:
    any of them
}