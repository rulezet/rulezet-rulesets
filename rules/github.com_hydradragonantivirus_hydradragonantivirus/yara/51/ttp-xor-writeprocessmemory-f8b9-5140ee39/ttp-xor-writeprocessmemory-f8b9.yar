rule TTP_XOR_WriteProcessMemory_f8b9 {
  strings:
    $key_f8b9 = { af cb [2] 9d e9 [2] 9b dc [2] b5 dc [2] 8a c0 }

  condition:
    any of them
}