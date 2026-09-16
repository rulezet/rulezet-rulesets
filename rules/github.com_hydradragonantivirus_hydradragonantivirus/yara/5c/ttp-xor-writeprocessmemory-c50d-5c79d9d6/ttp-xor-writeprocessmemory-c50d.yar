rule TTP_XOR_WriteProcessMemory_c50d {
  strings:
    $key_c50d = { 92 7f [2] a0 5d [2] a6 68 [2] 88 68 [2] b7 74 }

  condition:
    any of them
}