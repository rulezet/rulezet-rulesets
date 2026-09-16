rule TTP_XOR_WriteProcessMemory_4ea4 {
  strings:
    $key_4ea4 = { 19 d6 [2] 2b f4 [2] 2d c1 [2] 03 c1 [2] 3c dd }

  condition:
    any of them
}