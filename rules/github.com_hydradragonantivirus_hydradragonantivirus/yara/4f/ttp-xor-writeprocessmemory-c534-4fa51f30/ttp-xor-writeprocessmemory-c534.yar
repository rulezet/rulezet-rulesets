rule TTP_XOR_WriteProcessMemory_c534 {
  strings:
    $key_c534 = { 92 46 [2] a0 64 [2] a6 51 [2] 88 51 [2] b7 4d }

  condition:
    any of them
}