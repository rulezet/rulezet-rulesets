rule TTP_XOR_WriteProcessMemory_0178 {
  strings:
    $key_0178 = { 56 0a [2] 64 28 [2] 62 1d [2] 4c 1d [2] 73 01 }

  condition:
    any of them
}