rule TTP_XOR_WriteProcessMemory_7a8d {
  strings:
    $key_7a8d = { 2d ff [2] 1f dd [2] 19 e8 [2] 37 e8 [2] 08 f4 }

  condition:
    any of them
}