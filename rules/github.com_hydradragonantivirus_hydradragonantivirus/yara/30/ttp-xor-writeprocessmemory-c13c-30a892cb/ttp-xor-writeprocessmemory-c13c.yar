rule TTP_XOR_WriteProcessMemory_c13c {
  strings:
    $key_c13c = { 96 4e [2] a4 6c [2] a2 59 [2] 8c 59 [2] b3 45 }

  condition:
    any of them
}