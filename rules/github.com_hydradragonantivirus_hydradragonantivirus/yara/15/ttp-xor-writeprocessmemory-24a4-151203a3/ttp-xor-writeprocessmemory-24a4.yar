rule TTP_XOR_WriteProcessMemory_24a4 {
  strings:
    $key_24a4 = { 73 d6 [2] 41 f4 [2] 47 c1 [2] 69 c1 [2] 56 dd }

  condition:
    any of them
}