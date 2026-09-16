rule TTP_XOR_WriteProcessMemory_0374 {
  strings:
    $key_0374 = { 54 06 [2] 66 24 [2] 60 11 [2] 4e 11 [2] 71 0d }

  condition:
    any of them
}