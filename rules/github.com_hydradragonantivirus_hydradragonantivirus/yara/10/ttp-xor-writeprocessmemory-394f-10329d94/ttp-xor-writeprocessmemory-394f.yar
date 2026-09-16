rule TTP_XOR_WriteProcessMemory_394f {
  strings:
    $key_394f = { 6e 3d [2] 5c 1f [2] 5a 2a [2] 74 2a [2] 4b 36 }

  condition:
    any of them
}