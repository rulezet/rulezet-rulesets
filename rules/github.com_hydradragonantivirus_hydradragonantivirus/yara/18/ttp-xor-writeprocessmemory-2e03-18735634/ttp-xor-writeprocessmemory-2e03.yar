rule TTP_XOR_WriteProcessMemory_2e03 {
  strings:
    $key_2e03 = { 79 71 [2] 4b 53 [2] 4d 66 [2] 63 66 [2] 5c 7a }

  condition:
    any of them
}