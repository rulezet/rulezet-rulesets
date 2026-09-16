rule TTP_XOR_WriteProcessMemory_ca58 {
  strings:
    $key_ca58 = { 9d 2a [2] af 08 [2] a9 3d [2] 87 3d [2] b8 21 }

  condition:
    any of them
}