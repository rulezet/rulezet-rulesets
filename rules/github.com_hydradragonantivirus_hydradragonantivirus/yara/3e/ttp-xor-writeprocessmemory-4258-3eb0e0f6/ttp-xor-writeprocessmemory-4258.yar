rule TTP_XOR_WriteProcessMemory_4258 {
  strings:
    $key_4258 = { 15 2a [2] 27 08 [2] 21 3d [2] 0f 3d [2] 30 21 }

  condition:
    any of them
}