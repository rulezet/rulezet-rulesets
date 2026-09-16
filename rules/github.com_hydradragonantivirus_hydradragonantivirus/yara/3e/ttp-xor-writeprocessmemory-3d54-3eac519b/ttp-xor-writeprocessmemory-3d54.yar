rule TTP_XOR_WriteProcessMemory_3d54 {
  strings:
    $key_3d54 = { 6a 26 [2] 58 04 [2] 5e 31 [2] 70 31 [2] 4f 2d }

  condition:
    any of them
}