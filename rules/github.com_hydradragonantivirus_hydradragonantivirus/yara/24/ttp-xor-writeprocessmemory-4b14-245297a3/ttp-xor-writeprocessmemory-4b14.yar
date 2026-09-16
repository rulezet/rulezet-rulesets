rule TTP_XOR_WriteProcessMemory_4b14 {
  strings:
    $key_4b14 = { 1c 66 [2] 2e 44 [2] 28 71 [2] 06 71 [2] 39 6d }

  condition:
    any of them
}