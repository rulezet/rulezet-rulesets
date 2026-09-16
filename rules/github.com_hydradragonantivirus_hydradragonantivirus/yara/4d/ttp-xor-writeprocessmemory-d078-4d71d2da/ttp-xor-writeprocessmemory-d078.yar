rule TTP_XOR_WriteProcessMemory_d078 {
  strings:
    $key_d078 = { 87 0a [2] b5 28 [2] b3 1d [2] 9d 1d [2] a2 01 }

  condition:
    any of them
}