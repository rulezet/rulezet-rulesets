rule TTP_XOR_WriteProcessMemory_1238 {
  strings:
    $key_1238 = { 45 4a [2] 77 68 [2] 71 5d [2] 5f 5d [2] 60 41 }

  condition:
    any of them
}