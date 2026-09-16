rule TTP_XOR_WriteProcessMemory_d068 {
  strings:
    $key_d068 = { 87 1a [2] b5 38 [2] b3 0d [2] 9d 0d [2] a2 11 }

  condition:
    any of them
}