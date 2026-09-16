rule TTP_XOR_WriteProcessMemory_feb9 {
  strings:
    $key_feb9 = { a9 cb [2] 9b e9 [2] 9d dc [2] b3 dc [2] 8c c0 }

  condition:
    any of them
}