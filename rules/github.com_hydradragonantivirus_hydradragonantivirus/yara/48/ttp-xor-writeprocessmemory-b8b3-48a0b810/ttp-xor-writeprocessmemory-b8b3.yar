rule TTP_XOR_WriteProcessMemory_b8b3 {
  strings:
    $key_b8b3 = { ef c1 [2] dd e3 [2] db d6 [2] f5 d6 [2] ca ca }

  condition:
    any of them
}