rule TTP_XOR_WriteProcessMemory_5324 {
  strings:
    $key_5324 = { 04 56 [2] 36 74 [2] 30 41 [2] 1e 41 [2] 21 5d }

  condition:
    any of them
}