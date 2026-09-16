rule TTP_XOR_WriteProcessMemory_e901 {
  strings:
    $key_e901 = { be 73 [2] 8c 51 [2] 8a 64 [2] a4 64 [2] 9b 78 }

  condition:
    any of them
}