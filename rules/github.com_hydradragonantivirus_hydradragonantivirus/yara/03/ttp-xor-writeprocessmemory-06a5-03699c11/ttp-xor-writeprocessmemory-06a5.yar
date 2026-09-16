rule TTP_XOR_WriteProcessMemory_06a5 {
  strings:
    $key_06a5 = { 51 d7 [2] 63 f5 [2] 65 c0 [2] 4b c0 [2] 74 dc }

  condition:
    any of them
}