rule TTP_XOR_WriteProcessMemory_2bb6 {
  strings:
    $key_2bb6 = { 7c c4 [2] 4e e6 [2] 48 d3 [2] 66 d3 [2] 59 cf }

  condition:
    any of them
}