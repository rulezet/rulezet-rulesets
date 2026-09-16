rule TTP_XOR_WriteProcessMemory_d434 {
  strings:
    $key_d434 = { 83 46 [2] b1 64 [2] b7 51 [2] 99 51 [2] a6 4d }

  condition:
    any of them
}