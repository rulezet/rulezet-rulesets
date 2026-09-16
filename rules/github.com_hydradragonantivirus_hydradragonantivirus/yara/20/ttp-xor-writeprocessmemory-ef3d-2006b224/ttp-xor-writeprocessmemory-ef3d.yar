rule TTP_XOR_WriteProcessMemory_ef3d {
  strings:
    $key_ef3d = { b8 4f [2] 8a 6d [2] 8c 58 [2] a2 58 [2] 9d 44 }

  condition:
    any of them
}