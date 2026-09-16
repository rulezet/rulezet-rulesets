rule TTP_XOR_WriteProcessMemory_b8b1 {
  strings:
    $key_b8b1 = { ef c3 [2] dd e1 [2] db d4 [2] f5 d4 [2] ca c8 }

  condition:
    any of them
}