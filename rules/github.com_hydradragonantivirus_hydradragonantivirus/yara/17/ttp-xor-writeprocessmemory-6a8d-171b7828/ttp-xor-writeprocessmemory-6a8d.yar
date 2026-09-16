rule TTP_XOR_WriteProcessMemory_6a8d {
  strings:
    $key_6a8d = { 3d ff [2] 0f dd [2] 09 e8 [2] 27 e8 [2] 18 f4 }

  condition:
    any of them
}