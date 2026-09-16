rule TTP_XOR_WriteProcessMemory_24e6 {
  strings:
    $key_24e6 = { 73 94 [2] 41 b6 [2] 47 83 [2] 69 83 [2] 56 9f }

  condition:
    any of them
}