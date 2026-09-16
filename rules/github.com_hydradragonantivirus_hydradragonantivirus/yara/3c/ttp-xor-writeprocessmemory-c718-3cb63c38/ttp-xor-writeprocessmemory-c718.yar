rule TTP_XOR_WriteProcessMemory_c718 {
  strings:
    $key_c718 = { 90 6a [2] a2 48 [2] a4 7d [2] 8a 7d [2] b5 61 }

  condition:
    any of them
}