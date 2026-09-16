rule TTP_XOR_WriteProcessMemory_fc12 {
  strings:
    $key_fc12 = { ab 60 [2] 99 42 [2] 9f 77 [2] b1 77 [2] 8e 6b }

  condition:
    any of them
}