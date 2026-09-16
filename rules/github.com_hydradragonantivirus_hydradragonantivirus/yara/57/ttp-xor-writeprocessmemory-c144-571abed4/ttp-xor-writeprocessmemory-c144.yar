rule TTP_XOR_WriteProcessMemory_c144 {
  strings:
    $key_c144 = { 96 36 [2] a4 14 [2] a2 21 [2] 8c 21 [2] b3 3d }

  condition:
    any of them
}