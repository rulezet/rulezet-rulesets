rule TTP_XOR_WriteProcessMemory_5b33 {
  strings:
    $key_5b33 = { 0c 41 [2] 3e 63 [2] 38 56 [2] 16 56 [2] 29 4a }

  condition:
    any of them
}