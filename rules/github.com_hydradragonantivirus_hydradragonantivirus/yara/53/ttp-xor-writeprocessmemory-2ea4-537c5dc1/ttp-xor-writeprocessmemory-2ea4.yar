rule TTP_XOR_WriteProcessMemory_2ea4 {
  strings:
    $key_2ea4 = { 79 d6 [2] 4b f4 [2] 4d c1 [2] 63 c1 [2] 5c dd }

  condition:
    any of them
}