rule TTP_XOR_WriteProcessMemory_1e23 {
  strings:
    $key_1e23 = { 49 51 [2] 7b 73 [2] 7d 46 [2] 53 46 [2] 6c 5a }

  condition:
    any of them
}