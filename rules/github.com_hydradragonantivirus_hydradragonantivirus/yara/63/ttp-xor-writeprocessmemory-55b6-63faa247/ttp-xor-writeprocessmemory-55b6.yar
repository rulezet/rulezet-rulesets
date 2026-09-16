rule TTP_XOR_WriteProcessMemory_55b6 {
  strings:
    $key_55b6 = { 02 c4 [2] 30 e6 [2] 36 d3 [2] 18 d3 [2] 27 cf }

  condition:
    any of them
}