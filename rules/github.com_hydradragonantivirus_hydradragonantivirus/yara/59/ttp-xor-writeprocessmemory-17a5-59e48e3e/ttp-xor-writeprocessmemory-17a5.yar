rule TTP_XOR_WriteProcessMemory_17a5 {
  strings:
    $key_17a5 = { 40 d7 [2] 72 f5 [2] 74 c0 [2] 5a c0 [2] 65 dc }

  condition:
    any of them
}