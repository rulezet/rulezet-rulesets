rule TTP_XOR_WriteProcessMemory_d026 {
  strings:
    $key_d026 = { 87 54 [2] b5 76 [2] b3 43 [2] 9d 43 [2] a2 5f }

  condition:
    any of them
}