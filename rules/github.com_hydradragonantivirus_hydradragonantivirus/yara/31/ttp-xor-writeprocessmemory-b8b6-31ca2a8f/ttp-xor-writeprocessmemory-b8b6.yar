rule TTP_XOR_WriteProcessMemory_b8b6 {
  strings:
    $key_b8b6 = { ef c4 [2] dd e6 [2] db d3 [2] f5 d3 [2] ca cf }

  condition:
    any of them
}