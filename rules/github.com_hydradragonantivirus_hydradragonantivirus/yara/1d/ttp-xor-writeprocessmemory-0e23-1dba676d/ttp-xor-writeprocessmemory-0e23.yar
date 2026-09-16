rule TTP_XOR_WriteProcessMemory_0e23 {
  strings:
    $key_0e23 = { 59 51 [2] 6b 73 [2] 6d 46 [2] 43 46 [2] 7c 5a }

  condition:
    any of them
}