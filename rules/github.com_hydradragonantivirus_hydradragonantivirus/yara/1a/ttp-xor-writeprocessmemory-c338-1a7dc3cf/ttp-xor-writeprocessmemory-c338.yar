rule TTP_XOR_WriteProcessMemory_c338 {
  strings:
    $key_c338 = { 94 4a [2] a6 68 [2] a0 5d [2] 8e 5d [2] b1 41 }

  condition:
    any of them
}