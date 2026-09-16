rule TTP_XOR_WriteProcessMemory_1603 {
  strings:
    $key_1603 = { 41 71 [2] 73 53 [2] 75 66 [2] 5b 66 [2] 64 7a }

  condition:
    any of them
}