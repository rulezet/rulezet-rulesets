rule TTP_XOR_WriteProcessMemory_ef74 {
  strings:
    $key_ef74 = { b8 06 [2] 8a 24 [2] 8c 11 [2] a2 11 [2] 9d 0d }

  condition:
    any of them
}