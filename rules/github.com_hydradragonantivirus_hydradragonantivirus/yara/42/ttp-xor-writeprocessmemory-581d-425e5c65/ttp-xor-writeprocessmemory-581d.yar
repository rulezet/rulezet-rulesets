rule TTP_XOR_WriteProcessMemory_581d {
  strings:
    $key_581d = { 0f 6f [2] 3d 4d [2] 3b 78 [2] 15 78 [2] 2a 64 }

  condition:
    any of them
}