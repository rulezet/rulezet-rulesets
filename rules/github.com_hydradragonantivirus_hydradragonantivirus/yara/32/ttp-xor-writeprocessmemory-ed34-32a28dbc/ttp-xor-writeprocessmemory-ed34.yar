rule TTP_XOR_WriteProcessMemory_ed34 {
  strings:
    $key_ed34 = { ba 46 [2] 88 64 [2] 8e 51 [2] a0 51 [2] 9f 4d }

  condition:
    any of them
}