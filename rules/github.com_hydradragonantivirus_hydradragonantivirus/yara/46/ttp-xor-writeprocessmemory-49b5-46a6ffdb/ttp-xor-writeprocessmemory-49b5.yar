rule TTP_XOR_WriteProcessMemory_49b5 {
  strings:
    $key_49b5 = { 1e c7 [2] 2c e5 [2] 2a d0 [2] 04 d0 [2] 3b cc }

  condition:
    any of them
}