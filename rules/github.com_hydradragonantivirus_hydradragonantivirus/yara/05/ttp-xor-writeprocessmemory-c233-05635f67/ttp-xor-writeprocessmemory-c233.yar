rule TTP_XOR_WriteProcessMemory_c233 {
  strings:
    $key_c233 = { 95 41 [2] a7 63 [2] a1 56 [2] 8f 56 [2] b0 4a }

  condition:
    any of them
}