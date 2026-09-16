rule TTP_XOR_WriteProcessMemory_eac2 {
  strings:
    $key_eac2 = { bd b0 [2] 8f 92 [2] 89 a7 [2] a7 a7 [2] 98 bb }

  condition:
    any of them
}