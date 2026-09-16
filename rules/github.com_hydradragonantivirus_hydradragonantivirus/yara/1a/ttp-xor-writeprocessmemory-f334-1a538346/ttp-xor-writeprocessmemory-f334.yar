rule TTP_XOR_WriteProcessMemory_f334 {
  strings:
    $key_f334 = { a4 46 [2] 96 64 [2] 90 51 [2] be 51 [2] 81 4d }

  condition:
    any of them
}