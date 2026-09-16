rule TTP_XOR_WriteProcessMemory_6a9d {
  strings:
    $key_6a9d = { 3d ef [2] 0f cd [2] 09 f8 [2] 27 f8 [2] 18 e4 }

  condition:
    any of them
}