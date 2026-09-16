rule TTP_XOR_WriteProcessMemory_2f03 {
  strings:
    $key_2f03 = { 78 71 [2] 4a 53 [2] 4c 66 [2] 62 66 [2] 5d 7a }

  condition:
    any of them
}