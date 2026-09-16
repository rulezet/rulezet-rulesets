rule TTP_XOR_WriteProcessMemory_d578 {
  strings:
    $key_d578 = { 82 0a [2] b0 28 [2] b6 1d [2] 98 1d [2] a7 01 }

  condition:
    any of them
}