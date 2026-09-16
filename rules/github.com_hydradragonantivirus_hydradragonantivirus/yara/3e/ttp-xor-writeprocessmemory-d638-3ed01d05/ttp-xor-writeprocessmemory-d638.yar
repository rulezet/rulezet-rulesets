rule TTP_XOR_WriteProcessMemory_d638 {
  strings:
    $key_d638 = { 81 4a [2] b3 68 [2] b5 5d [2] 9b 5d [2] a4 41 }

  condition:
    any of them
}