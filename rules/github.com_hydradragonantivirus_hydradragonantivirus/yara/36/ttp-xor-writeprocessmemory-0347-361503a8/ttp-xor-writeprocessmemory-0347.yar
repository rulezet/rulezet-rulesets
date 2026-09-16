rule TTP_XOR_WriteProcessMemory_0347 {
  strings:
    $key_0347 = { 54 35 [2] 66 17 [2] 60 22 [2] 4e 22 [2] 71 3e }

  condition:
    any of them
}