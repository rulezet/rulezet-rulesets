rule TTP_XOR_WriteProcessMemory_7803 {
  strings:
    $key_7803 = { 2f 71 [2] 1d 53 [2] 1b 66 [2] 35 66 [2] 0a 7a }

  condition:
    any of them
}