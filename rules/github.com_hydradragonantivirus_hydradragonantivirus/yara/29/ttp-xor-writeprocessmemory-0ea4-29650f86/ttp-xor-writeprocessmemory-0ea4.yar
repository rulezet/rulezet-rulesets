rule TTP_XOR_WriteProcessMemory_0ea4 {
  strings:
    $key_0ea4 = { 59 d6 [2] 6b f4 [2] 6d c1 [2] 43 c1 [2] 7c dd }

  condition:
    any of them
}