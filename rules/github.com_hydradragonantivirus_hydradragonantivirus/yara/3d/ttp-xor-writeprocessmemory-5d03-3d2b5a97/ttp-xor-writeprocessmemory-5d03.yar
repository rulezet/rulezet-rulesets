rule TTP_XOR_WriteProcessMemory_5d03 {
  strings:
    $key_5d03 = { 0a 71 [2] 38 53 [2] 3e 66 [2] 10 66 [2] 2f 7a }

  condition:
    any of them
}