rule TTP_XOR_WriteProcessMemory_0640 {
  strings:
    $key_0640 = { 51 32 [2] 63 10 [2] 65 25 [2] 4b 25 [2] 74 39 }

  condition:
    any of them
}