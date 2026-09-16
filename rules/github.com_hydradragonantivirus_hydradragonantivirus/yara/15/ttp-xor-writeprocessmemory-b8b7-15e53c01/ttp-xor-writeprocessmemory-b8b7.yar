rule TTP_XOR_WriteProcessMemory_b8b7 {
  strings:
    $key_b8b7 = { ef c5 [2] dd e7 [2] db d2 [2] f5 d2 [2] ca ce }

  condition:
    any of them
}