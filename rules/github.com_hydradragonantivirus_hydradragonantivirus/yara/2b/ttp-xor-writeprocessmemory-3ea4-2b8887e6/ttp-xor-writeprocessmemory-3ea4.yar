rule TTP_XOR_WriteProcessMemory_3ea4 {
  strings:
    $key_3ea4 = { 69 d6 [2] 5b f4 [2] 5d c1 [2] 73 c1 [2] 4c dd }

  condition:
    any of them
}