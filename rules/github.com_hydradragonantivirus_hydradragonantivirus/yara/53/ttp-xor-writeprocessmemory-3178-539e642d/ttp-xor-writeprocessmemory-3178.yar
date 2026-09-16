rule TTP_XOR_WriteProcessMemory_3178 {
  strings:
    $key_3178 = { 66 0a [2] 54 28 [2] 52 1d [2] 7c 1d [2] 43 01 }

  condition:
    any of them
}