rule TTP_XOR_WriteProcessMemory_c86d {
  strings:
    $key_c86d = { 9f 1f [2] ad 3d [2] ab 08 [2] 85 08 [2] ba 14 }

  condition:
    any of them
}