rule TTP_XOR_WriteProcessMemory_2e23 {
  strings:
    $key_2e23 = { 79 51 [2] 4b 73 [2] 4d 46 [2] 63 46 [2] 5c 5a }

  condition:
    any of them
}