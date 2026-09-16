rule TTP_XOR_WriteProcessMemory_3118 {
  strings:
    $key_3118 = { 66 6a [2] 54 48 [2] 52 7d [2] 7c 7d [2] 43 61 }

  condition:
    any of them
}