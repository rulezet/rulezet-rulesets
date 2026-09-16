rule TTP_XOR_WriteProcessMemory_b74f {
  strings:
    $key_b74f = { e0 3d [2] d2 1f [2] d4 2a [2] fa 2a [2] c5 36 }

  condition:
    any of them
}