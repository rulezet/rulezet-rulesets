rule TTP_XOR_WriteProcessMemory_d21b {
  strings:
    $key_d21b = { 85 69 [2] b7 4b [2] b1 7e [2] 9f 7e [2] a0 62 }

  condition:
    any of them
}