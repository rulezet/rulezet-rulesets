rule TTP_XOR_WriteProcessMemory_ef32 {
  strings:
    $key_ef32 = { b8 40 [2] 8a 62 [2] 8c 57 [2] a2 57 [2] 9d 4b }

  condition:
    any of them
}