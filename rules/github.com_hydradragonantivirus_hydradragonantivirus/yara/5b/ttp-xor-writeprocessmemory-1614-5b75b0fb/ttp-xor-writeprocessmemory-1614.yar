rule TTP_XOR_WriteProcessMemory_1614 {
  strings:
    $key_1614 = { 41 66 [2] 73 44 [2] 75 71 [2] 5b 71 [2] 64 6d }

  condition:
    any of them
}