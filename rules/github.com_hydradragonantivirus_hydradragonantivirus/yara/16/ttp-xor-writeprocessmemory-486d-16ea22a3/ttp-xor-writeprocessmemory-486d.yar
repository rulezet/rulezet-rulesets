rule TTP_XOR_WriteProcessMemory_486d {
  strings:
    $key_486d = { 1f 1f [2] 2d 3d [2] 2b 08 [2] 05 08 [2] 3a 14 }

  condition:
    any of them
}