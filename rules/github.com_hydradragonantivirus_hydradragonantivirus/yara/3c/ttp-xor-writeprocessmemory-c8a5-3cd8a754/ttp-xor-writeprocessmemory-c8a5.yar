rule TTP_XOR_WriteProcessMemory_c8a5 {
  strings:
    $key_c8a5 = { 9f d7 [2] ad f5 [2] ab c0 [2] 85 c0 [2] ba dc }

  condition:
    any of them
}