rule TTP_XOR_WriteProcessMemory_c51d {
  strings:
    $key_c51d = { 92 6f [2] a0 4d [2] a6 78 [2] 88 78 [2] b7 64 }

  condition:
    any of them
}