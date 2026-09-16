rule TTP_XOR_WriteProcessMemory_c47d {
  strings:
    $key_c47d = { 93 0f [2] a1 2d [2] a7 18 [2] 89 18 [2] b6 04 }

  condition:
    any of them
}