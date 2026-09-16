rule TTP_XOR_WriteProcessMemory_6714 {
  strings:
    $key_6714 = { 30 66 [2] 02 44 [2] 04 71 [2] 2a 71 [2] 15 6d }

  condition:
    any of them
}