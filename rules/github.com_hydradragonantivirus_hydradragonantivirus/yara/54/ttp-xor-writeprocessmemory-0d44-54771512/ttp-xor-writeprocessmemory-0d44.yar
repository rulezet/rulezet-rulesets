rule TTP_XOR_WriteProcessMemory_0d44 {
  strings:
    $key_0d44 = { 5a 36 [2] 68 14 [2] 6e 21 [2] 40 21 [2] 7f 3d }

  condition:
    any of them
}