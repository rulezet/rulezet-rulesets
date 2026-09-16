rule TTP_XOR_WriteProcessMemory_e454 {
  strings:
    $key_e454 = { b3 26 [2] 81 04 [2] 87 31 [2] a9 31 [2] 96 2d }

  condition:
    any of them
}