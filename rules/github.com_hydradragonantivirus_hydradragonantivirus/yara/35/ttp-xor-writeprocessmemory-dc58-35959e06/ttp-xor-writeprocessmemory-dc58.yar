rule TTP_XOR_WriteProcessMemory_dc58 {
  strings:
    $key_dc58 = { 8b 2a [2] b9 08 [2] bf 3d [2] 91 3d [2] ae 21 }

  condition:
    any of them
}