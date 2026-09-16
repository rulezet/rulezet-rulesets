rule TTP_XOR_WriteProcessMemory_d428 {
  strings:
    $key_d428 = { 83 5a [2] b1 78 [2] b7 4d [2] 99 4d [2] a6 51 }

  condition:
    any of them
}