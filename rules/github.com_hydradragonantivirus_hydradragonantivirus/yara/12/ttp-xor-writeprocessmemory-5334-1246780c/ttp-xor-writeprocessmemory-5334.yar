rule TTP_XOR_WriteProcessMemory_5334 {
  strings:
    $key_5334 = { 04 46 [2] 36 64 [2] 30 51 [2] 1e 51 [2] 21 4d }

  condition:
    any of them
}