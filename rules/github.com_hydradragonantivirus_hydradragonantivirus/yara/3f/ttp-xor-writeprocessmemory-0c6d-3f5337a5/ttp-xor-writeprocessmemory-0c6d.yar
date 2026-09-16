rule TTP_XOR_WriteProcessMemory_0c6d {
  strings:
    $key_0c6d = { 5b 1f [2] 69 3d [2] 6f 08 [2] 41 08 [2] 7e 14 }

  condition:
    any of them
}