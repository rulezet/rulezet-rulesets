rule TTP_XOR_WriteProcessMemory_f528 {
  strings:
    $key_f528 = { a2 5a [2] 90 78 [2] 96 4d [2] b8 4d [2] 87 51 }

  condition:
    any of them
}