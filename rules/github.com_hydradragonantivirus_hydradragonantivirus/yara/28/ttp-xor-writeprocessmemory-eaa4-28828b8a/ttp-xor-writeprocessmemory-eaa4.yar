rule TTP_XOR_WriteProcessMemory_eaa4 {
  strings:
    $key_eaa4 = { bd d6 [2] 8f f4 [2] 89 c1 [2] a7 c1 [2] 98 dd }

  condition:
    any of them
}