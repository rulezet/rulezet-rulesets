rule TTP_XOR_WriteProcessMemory_80b6 {
  strings:
    $key_80b6 = { d7 c4 [2] e5 e6 [2] e3 d3 [2] cd d3 [2] f2 cf }

  condition:
    any of them
}