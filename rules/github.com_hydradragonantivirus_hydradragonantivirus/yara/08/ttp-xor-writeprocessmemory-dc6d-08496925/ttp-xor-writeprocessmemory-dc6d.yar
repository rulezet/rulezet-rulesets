rule TTP_XOR_WriteProcessMemory_dc6d {
  strings:
    $key_dc6d = { 8b 1f [2] b9 3d [2] bf 08 [2] 91 08 [2] ae 14 }

  condition:
    any of them
}