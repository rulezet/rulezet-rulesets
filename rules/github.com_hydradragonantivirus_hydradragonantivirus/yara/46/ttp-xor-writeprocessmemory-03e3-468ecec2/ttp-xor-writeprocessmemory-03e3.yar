rule TTP_XOR_WriteProcessMemory_03e3 {
  strings:
    $key_03e3 = { 54 91 [2] 66 b3 [2] 60 86 [2] 4e 86 [2] 71 9a }

  condition:
    any of them
}