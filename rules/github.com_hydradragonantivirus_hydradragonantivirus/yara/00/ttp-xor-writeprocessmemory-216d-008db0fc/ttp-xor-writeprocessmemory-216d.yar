rule TTP_XOR_WriteProcessMemory_216d {
  strings:
    $key_216d = { 76 1f [2] 44 3d [2] 42 08 [2] 6c 08 [2] 53 14 }

  condition:
    any of them
}