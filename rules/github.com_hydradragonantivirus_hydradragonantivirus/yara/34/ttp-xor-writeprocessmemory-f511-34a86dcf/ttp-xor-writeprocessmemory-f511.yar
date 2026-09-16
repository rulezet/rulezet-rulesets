rule TTP_XOR_WriteProcessMemory_f511 {
  strings:
    $key_f511 = { a2 63 [2] 90 41 [2] 96 74 [2] b8 74 [2] 87 68 }

  condition:
    any of them
}