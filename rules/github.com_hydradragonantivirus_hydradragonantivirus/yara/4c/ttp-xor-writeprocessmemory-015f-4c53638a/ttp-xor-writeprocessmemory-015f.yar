rule TTP_XOR_WriteProcessMemory_015f {
  strings:
    $key_015f = { 56 2d [2] 64 0f [2] 62 3a [2] 4c 3a [2] 73 26 }

  condition:
    any of them
}