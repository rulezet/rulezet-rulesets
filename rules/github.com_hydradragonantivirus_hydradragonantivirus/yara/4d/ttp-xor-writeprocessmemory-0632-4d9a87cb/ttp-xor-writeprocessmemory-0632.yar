rule TTP_XOR_WriteProcessMemory_0632 {
  strings:
    $key_0632 = { 51 40 [2] 63 62 [2] 65 57 [2] 4b 57 [2] 74 4b }

  condition:
    any of them
}