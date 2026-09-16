rule TTP_XOR_WriteProcessMemory_dc3d {
  strings:
    $key_dc3d = { 8b 4f [2] b9 6d [2] bf 58 [2] 91 58 [2] ae 44 }

  condition:
    any of them
}