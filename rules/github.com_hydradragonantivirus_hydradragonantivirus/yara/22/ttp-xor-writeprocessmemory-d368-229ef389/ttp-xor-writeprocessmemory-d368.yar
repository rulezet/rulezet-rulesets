rule TTP_XOR_WriteProcessMemory_d368 {
  strings:
    $key_d368 = { 84 1a [2] b6 38 [2] b0 0d [2] 9e 0d [2] a1 11 }

  condition:
    any of them
}