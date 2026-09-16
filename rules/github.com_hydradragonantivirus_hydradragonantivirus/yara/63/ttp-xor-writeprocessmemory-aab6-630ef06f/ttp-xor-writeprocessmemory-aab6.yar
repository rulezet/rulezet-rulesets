rule TTP_XOR_WriteProcessMemory_aab6 {
  strings:
    $key_aab6 = { fd c4 [2] cf e6 [2] c9 d3 [2] e7 d3 [2] d8 cf }

  condition:
    any of them
}