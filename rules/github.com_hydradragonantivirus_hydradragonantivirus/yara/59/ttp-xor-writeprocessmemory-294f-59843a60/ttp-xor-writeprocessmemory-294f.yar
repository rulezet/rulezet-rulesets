rule TTP_XOR_WriteProcessMemory_294f {
  strings:
    $key_294f = { 7e 3d [2] 4c 1f [2] 4a 2a [2] 64 2a [2] 5b 36 }

  condition:
    any of them
}