rule TTP_XOR_WriteProcessMemory_e26d {
  strings:
    $key_e26d = { b5 1f [2] 87 3d [2] 81 08 [2] af 08 [2] 90 14 }

  condition:
    any of them
}