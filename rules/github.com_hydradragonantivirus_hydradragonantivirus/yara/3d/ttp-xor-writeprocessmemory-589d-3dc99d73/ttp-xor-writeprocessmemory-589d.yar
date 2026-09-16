rule TTP_XOR_WriteProcessMemory_589d {
  strings:
    $key_589d = { 0f ef [2] 3d cd [2] 3b f8 [2] 15 f8 [2] 2a e4 }

  condition:
    any of them
}