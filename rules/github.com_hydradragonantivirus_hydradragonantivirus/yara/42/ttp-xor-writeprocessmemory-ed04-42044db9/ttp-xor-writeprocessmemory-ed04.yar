rule TTP_XOR_WriteProcessMemory_ed04 {
  strings:
    $key_ed04 = { ba 76 [2] 88 54 [2] 8e 61 [2] a0 61 [2] 9f 7d }

  condition:
    any of them
}