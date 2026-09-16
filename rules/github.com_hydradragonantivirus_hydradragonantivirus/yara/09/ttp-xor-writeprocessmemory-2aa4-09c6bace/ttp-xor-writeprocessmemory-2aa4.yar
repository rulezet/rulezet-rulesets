rule TTP_XOR_WriteProcessMemory_2aa4 {
  strings:
    $key_2aa4 = { 7d d6 [2] 4f f4 [2] 49 c1 [2] 67 c1 [2] 58 dd }

  condition:
    any of them
}