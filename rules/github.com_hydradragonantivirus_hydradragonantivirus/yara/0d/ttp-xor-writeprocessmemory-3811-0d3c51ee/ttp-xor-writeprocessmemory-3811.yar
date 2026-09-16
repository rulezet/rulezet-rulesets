rule TTP_XOR_WriteProcessMemory_3811 {
  strings:
    $key_3811 = { 6f 63 [2] 5d 41 [2] 5b 74 [2] 75 74 [2] 4a 68 }

  condition:
    any of them
}