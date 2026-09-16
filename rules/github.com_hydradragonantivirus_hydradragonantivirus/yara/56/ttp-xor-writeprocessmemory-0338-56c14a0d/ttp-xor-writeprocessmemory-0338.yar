rule TTP_XOR_WriteProcessMemory_0338 {
  strings:
    $key_0338 = { 54 4a [2] 66 68 [2] 60 5d [2] 4e 5d [2] 71 41 }

  condition:
    any of them
}