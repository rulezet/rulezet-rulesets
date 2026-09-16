rule TTP_XOR_WriteProcessMemory_ea40 {
  strings:
    $key_ea40 = { bd 32 [2] 8f 10 [2] 89 25 [2] a7 25 [2] 98 39 }

  condition:
    any of them
}