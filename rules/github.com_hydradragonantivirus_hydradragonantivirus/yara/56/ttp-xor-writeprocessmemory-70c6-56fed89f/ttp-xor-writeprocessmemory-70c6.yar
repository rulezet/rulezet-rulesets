rule TTP_XOR_WriteProcessMemory_70c6 {
  strings:
    $key_70c6 = { 27 b4 [2] 15 96 [2] 13 a3 [2] 3d a3 [2] 02 bf }

  condition:
    any of them
}