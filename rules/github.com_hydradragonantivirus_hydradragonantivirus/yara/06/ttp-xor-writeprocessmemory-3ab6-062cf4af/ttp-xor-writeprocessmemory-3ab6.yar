rule TTP_XOR_WriteProcessMemory_3ab6 {
  strings:
    $key_3ab6 = { 6d c4 [2] 5f e6 [2] 59 d3 [2] 77 d3 [2] 48 cf }

  condition:
    any of them
}