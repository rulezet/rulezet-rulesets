rule TTP_XOR_WriteProcessMemory_2e64 {
  strings:
    $key_2e64 = { 79 16 [2] 4b 34 [2] 4d 01 [2] 63 01 [2] 5c 1d }

  condition:
    any of them
}