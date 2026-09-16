rule TTP_XOR_WriteProcessMemory_0310 {
  strings:
    $key_0310 = { 54 62 [2] 66 40 [2] 60 75 [2] 4e 75 [2] 71 69 }

  condition:
    any of them
}