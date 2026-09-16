rule TTP_XOR_WriteProcessMemory_6f03 {
  strings:
    $key_6f03 = { 38 71 [2] 0a 53 [2] 0c 66 [2] 22 66 [2] 1d 7a }

  condition:
    any of them
}