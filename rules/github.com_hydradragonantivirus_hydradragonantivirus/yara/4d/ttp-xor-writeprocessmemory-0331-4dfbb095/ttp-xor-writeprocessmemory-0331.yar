rule TTP_XOR_WriteProcessMemory_0331 {
  strings:
    $key_0331 = { 54 43 [2] 66 61 [2] 60 54 [2] 4e 54 [2] 71 48 }

  condition:
    any of them
}