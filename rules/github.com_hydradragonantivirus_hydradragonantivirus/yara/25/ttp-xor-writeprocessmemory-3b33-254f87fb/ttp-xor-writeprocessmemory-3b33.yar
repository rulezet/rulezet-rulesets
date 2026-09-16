rule TTP_XOR_WriteProcessMemory_3b33 {
  strings:
    $key_3b33 = { 6c 41 [2] 5e 63 [2] 58 56 [2] 76 56 [2] 49 4a }

  condition:
    any of them
}