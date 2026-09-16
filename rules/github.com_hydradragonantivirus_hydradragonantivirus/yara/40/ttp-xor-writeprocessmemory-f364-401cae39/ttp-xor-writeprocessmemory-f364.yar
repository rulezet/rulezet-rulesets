rule TTP_XOR_WriteProcessMemory_f364 {
  strings:
    $key_f364 = { a4 16 [2] 96 34 [2] 90 01 [2] be 01 [2] 81 1d }

  condition:
    any of them
}