rule TTP_XOR_WriteProcessMemory_6ac4 {
  strings:
    $key_6ac4 = { 3d b6 [2] 0f 94 [2] 09 a1 [2] 27 a1 [2] 18 bd }

  condition:
    any of them
}