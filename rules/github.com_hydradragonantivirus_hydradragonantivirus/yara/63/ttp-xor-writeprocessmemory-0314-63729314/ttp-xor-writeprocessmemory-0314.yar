rule TTP_XOR_WriteProcessMemory_0314 {
  strings:
    $key_0314 = { 54 66 [2] 66 44 [2] 60 71 [2] 4e 71 [2] 71 6d }

  condition:
    any of them
}