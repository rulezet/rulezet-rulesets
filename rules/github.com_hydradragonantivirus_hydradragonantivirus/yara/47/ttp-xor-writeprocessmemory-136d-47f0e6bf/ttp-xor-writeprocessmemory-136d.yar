rule TTP_XOR_WriteProcessMemory_136d {
  strings:
    $key_136d = { 44 1f [2] 76 3d [2] 70 08 [2] 5e 08 [2] 61 14 }

  condition:
    any of them
}