rule TTP_XOR_WriteProcessMemory_ca44 {
  strings:
    $key_ca44 = { 9d 36 [2] af 14 [2] a9 21 [2] 87 21 [2] b8 3d }

  condition:
    any of them
}