rule TTP_XOR_WriteProcessMemory_d538 {
  strings:
    $key_d538 = { 82 4a [2] b0 68 [2] b6 5d [2] 98 5d [2] a7 41 }

  condition:
    any of them
}