rule TTP_XOR_WriteProcessMemory_3933 {
  strings:
    $key_3933 = { 6e 41 [2] 5c 63 [2] 5a 56 [2] 74 56 [2] 4b 4a }

  condition:
    any of them
}