rule TTP_XOR_WriteProcessMemory_5ea2 {
  strings:
    $key_5ea2 = { 09 d0 [2] 3b f2 [2] 3d c7 [2] 13 c7 [2] 2c db }

  condition:
    any of them
}