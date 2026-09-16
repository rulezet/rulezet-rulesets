rule TTP_XOR_WriteProcessMemory_7c6d {
  strings:
    $key_7c6d = { 2b 1f [2] 19 3d [2] 1f 08 [2] 31 08 [2] 0e 14 }

  condition:
    any of them
}