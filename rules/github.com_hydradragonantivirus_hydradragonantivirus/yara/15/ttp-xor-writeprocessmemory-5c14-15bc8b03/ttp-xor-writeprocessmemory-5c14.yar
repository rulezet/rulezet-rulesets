rule TTP_XOR_WriteProcessMemory_5c14 {
  strings:
    $key_5c14 = { 0b 66 [2] 39 44 [2] 3f 71 [2] 11 71 [2] 2e 6d }

  condition:
    any of them
}