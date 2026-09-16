rule TTP_XOR_WriteProcessMemory_e414 {
  strings:
    $key_e414 = { b3 66 [2] 81 44 [2] 87 71 [2] a9 71 [2] 96 6d }

  condition:
    any of them
}