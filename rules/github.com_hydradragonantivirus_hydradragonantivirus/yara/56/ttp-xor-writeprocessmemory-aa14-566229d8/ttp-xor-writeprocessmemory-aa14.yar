rule TTP_XOR_WriteProcessMemory_aa14 {
  strings:
    $key_aa14 = { fd 66 [2] cf 44 [2] c9 71 [2] e7 71 [2] d8 6d }

  condition:
    any of them
}