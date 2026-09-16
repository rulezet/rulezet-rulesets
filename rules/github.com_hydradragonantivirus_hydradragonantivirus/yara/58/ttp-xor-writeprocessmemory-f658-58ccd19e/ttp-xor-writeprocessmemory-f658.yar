rule TTP_XOR_WriteProcessMemory_f658 {
  strings:
    $key_f658 = { a1 2a [2] 93 08 [2] 95 3d [2] bb 3d [2] 84 21 }

  condition:
    any of them
}