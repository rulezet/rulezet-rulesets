rule TTP_XOR_WriteProcessMemory_c171 {
  strings:
    $key_c171 = { 96 03 [2] a4 21 [2] a2 14 [2] 8c 14 [2] b3 08 }

  condition:
    any of them
}