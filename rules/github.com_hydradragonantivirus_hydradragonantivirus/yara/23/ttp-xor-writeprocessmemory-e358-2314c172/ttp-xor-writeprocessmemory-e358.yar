rule TTP_XOR_WriteProcessMemory_e358 {
  strings:
    $key_e358 = { b4 2a [2] 86 08 [2] 80 3d [2] ae 3d [2] 91 21 }

  condition:
    any of them
}