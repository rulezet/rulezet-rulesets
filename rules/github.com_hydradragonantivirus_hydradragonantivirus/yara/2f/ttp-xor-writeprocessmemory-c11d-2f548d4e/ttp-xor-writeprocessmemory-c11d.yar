rule TTP_XOR_WriteProcessMemory_c11d {
  strings:
    $key_c11d = { 96 6f [2] a4 4d [2] a2 78 [2] 8c 78 [2] b3 64 }

  condition:
    any of them
}