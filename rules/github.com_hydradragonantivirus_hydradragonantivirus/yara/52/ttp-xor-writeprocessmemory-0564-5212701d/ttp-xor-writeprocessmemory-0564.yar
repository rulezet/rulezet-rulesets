rule TTP_XOR_WriteProcessMemory_0564 {
  strings:
    $key_0564 = { 52 16 [2] 60 34 [2] 66 01 [2] 48 01 [2] 77 1d }

  condition:
    any of them
}