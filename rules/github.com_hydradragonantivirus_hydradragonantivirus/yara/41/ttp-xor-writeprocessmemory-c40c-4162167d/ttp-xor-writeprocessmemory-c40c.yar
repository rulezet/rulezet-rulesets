rule TTP_XOR_WriteProcessMemory_c40c {
  strings:
    $key_c40c = { 93 7e [2] a1 5c [2] a7 69 [2] 89 69 [2] b6 75 }

  condition:
    any of them
}