rule TTP_XOR_WriteProcessMemory_6aa4 {
  strings:
    $key_6aa4 = { 3d d6 [2] 0f f4 [2] 09 c1 [2] 27 c1 [2] 18 dd }

  condition:
    any of them
}