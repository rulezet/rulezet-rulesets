rule TTP_XOR_WriteProcessMemory_c72c {
  strings:
    $key_c72c = { 90 5e [2] a2 7c [2] a4 49 [2] 8a 49 [2] b5 55 }

  condition:
    any of them
}