rule TTP_XOR_WriteProcessMemory_536d {
  strings:
    $key_536d = { 04 1f [2] 36 3d [2] 30 08 [2] 1e 08 [2] 21 14 }

  condition:
    any of them
}