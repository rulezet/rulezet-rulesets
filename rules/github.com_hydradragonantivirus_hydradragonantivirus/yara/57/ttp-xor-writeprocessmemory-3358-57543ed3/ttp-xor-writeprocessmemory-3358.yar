rule TTP_XOR_WriteProcessMemory_3358 {
  strings:
    $key_3358 = { 64 2a [2] 56 08 [2] 50 3d [2] 7e 3d [2] 41 21 }

  condition:
    any of them
}