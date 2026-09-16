rule TTP_XOR_WriteProcessMemory_2903 {
  strings:
    $key_2903 = { 7e 71 [2] 4c 53 [2] 4a 66 [2] 64 66 [2] 5b 7a }

  condition:
    any of them
}