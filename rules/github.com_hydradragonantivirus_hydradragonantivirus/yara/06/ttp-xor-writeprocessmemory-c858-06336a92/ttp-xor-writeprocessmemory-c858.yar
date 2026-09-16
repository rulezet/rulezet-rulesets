rule TTP_XOR_WriteProcessMemory_c858 {
  strings:
    $key_c858 = { 9f 2a [2] ad 08 [2] ab 3d [2] 85 3d [2] ba 21 }

  condition:
    any of them
}