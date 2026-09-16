rule TTP_XOR_WriteProcessMemory_c434 {
  strings:
    $key_c434 = { 93 46 [2] a1 64 [2] a7 51 [2] 89 51 [2] b6 4d }

  condition:
    any of them
}