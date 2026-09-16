rule TTP_XOR_WriteProcessMemory_d633 {
  strings:
    $key_d633 = { 81 41 [2] b3 63 [2] b5 56 [2] 9b 56 [2] a4 4a }

  condition:
    any of them
}