rule TTP_XOR_WriteProcessMemory_d344 {
  strings:
    $key_d344 = { 84 36 [2] b6 14 [2] b0 21 [2] 9e 21 [2] a1 3d }

  condition:
    any of them
}