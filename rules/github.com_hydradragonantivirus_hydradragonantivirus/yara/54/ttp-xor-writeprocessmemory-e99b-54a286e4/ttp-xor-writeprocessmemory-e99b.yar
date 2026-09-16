rule TTP_XOR_WriteProcessMemory_e99b {
  strings:
    $key_e99b = { be e9 [2] 8c cb [2] 8a fe [2] a4 fe [2] 9b e2 }

  condition:
    any of them
}