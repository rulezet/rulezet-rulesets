rule TTP_XOR_WriteProcessMemory_0d6d {
  strings:
    $key_0d6d = { 5a 1f [2] 68 3d [2] 6e 08 [2] 40 08 [2] 7f 14 }

  condition:
    any of them
}