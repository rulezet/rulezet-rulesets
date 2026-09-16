rule TTP_XOR_WriteProcessMemory_91c9 {
  strings:
    $key_91c9 = { c6 bb [2] f4 99 [2] f2 ac [2] dc ac [2] e3 b0 }

  condition:
    any of them
}