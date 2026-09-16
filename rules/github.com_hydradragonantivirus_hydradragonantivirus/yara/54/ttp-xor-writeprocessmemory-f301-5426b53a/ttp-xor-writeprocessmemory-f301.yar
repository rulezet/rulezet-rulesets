rule TTP_XOR_WriteProcessMemory_f301 {
  strings:
    $key_f301 = { a4 73 [2] 96 51 [2] 90 64 [2] be 64 [2] 81 78 }

  condition:
    any of them
}