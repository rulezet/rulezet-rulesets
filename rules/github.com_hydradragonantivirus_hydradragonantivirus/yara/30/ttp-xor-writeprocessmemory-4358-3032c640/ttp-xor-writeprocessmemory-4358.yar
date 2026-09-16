rule TTP_XOR_WriteProcessMemory_4358 {
  strings:
    $key_4358 = { 14 2a [2] 26 08 [2] 20 3d [2] 0e 3d [2] 31 21 }

  condition:
    any of them
}