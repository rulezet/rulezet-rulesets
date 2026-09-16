rule TTP_XOR_WriteProcessMemory_c8a7 {
  strings:
    $key_c8a7 = { 9f d5 [2] ad f7 [2] ab c2 [2] 85 c2 [2] ba de }

  condition:
    any of them
}