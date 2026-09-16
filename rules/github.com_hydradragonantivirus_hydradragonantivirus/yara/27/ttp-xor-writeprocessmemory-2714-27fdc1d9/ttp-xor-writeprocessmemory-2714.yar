rule TTP_XOR_WriteProcessMemory_2714 {
  strings:
    $key_2714 = { 70 66 [2] 42 44 [2] 44 71 [2] 6a 71 [2] 55 6d }

  condition:
    any of them
}