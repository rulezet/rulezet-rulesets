rule TTP_XOR_WriteProcessMemory_0334 {
  strings:
    $key_0334 = { 54 46 [2] 66 64 [2] 60 51 [2] 4e 51 [2] 71 4d }

  condition:
    any of them
}