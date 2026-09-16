rule TTP_XOR_WriteProcessMemory_4b4f {
  strings:
    $key_4b4f = { 1c 3d [2] 2e 1f [2] 28 2a [2] 06 2a [2] 39 36 }

  condition:
    any of them
}