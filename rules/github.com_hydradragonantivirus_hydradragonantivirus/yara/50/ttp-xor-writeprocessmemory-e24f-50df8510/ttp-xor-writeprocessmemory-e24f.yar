rule TTP_XOR_WriteProcessMemory_e24f {
  strings:
    $key_e24f = { b5 3d [2] 87 1f [2] 81 2a [2] af 2a [2] 90 36 }

  condition:
    any of them
}