rule TTP_XOR_WriteProcessMemory_c15c {
  strings:
    $key_c15c = { 96 2e [2] a4 0c [2] a2 39 [2] 8c 39 [2] b3 25 }

  condition:
    any of them
}