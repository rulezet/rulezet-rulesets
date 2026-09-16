rule TTP_XOR_WriteProcessMemory_7454 {
  strings:
    $key_7454 = { 23 26 [2] 11 04 [2] 17 31 [2] 39 31 [2] 06 2d }

  condition:
    any of them
}