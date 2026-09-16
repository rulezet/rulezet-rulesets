rule TTP_XOR_WriteProcessMemory_0d14 {
  strings:
    $key_0d14 = { 5a 66 [2] 68 44 [2] 6e 71 [2] 40 71 [2] 7f 6d }

  condition:
    any of them
}