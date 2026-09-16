rule TTP_XOR_WriteProcessMemory_c20d {
  strings:
    $key_c20d = { 95 7f [2] a7 5d [2] a1 68 [2] 8f 68 [2] b0 74 }

  condition:
    any of them
}