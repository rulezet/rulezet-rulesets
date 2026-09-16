rule TTP_XOR_WriteProcessMemory_354f {
  strings:
    $key_354f = { 62 3d [2] 50 1f [2] 56 2a [2] 78 2a [2] 47 36 }

  condition:
    any of them
}