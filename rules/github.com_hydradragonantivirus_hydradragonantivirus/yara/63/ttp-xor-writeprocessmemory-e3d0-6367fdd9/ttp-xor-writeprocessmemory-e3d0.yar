rule TTP_XOR_WriteProcessMemory_e3d0 {
  strings:
    $key_e3d0 = { b4 a2 [2] 86 80 [2] 80 b5 [2] ae b5 [2] 91 a9 }

  condition:
    any of them
}