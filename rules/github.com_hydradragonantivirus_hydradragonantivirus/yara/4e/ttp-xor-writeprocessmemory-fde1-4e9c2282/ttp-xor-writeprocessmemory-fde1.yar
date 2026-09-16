rule TTP_XOR_WriteProcessMemory_fde1 {
  strings:
    $key_fde1 = { aa 93 [2] 98 b1 [2] 9e 84 [2] b0 84 [2] 8f 98 }

  condition:
    any of them
}