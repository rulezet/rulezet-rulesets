rule TTP_XOR_WriteProcessMemory_e6a5 {
  strings:
    $key_e6a5 = { b1 d7 [2] 83 f5 [2] 85 c0 [2] ab c0 [2] 94 dc }

  condition:
    any of them
}