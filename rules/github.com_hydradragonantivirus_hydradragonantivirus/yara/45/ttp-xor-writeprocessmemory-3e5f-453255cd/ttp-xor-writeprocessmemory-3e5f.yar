rule TTP_XOR_WriteProcessMemory_3e5f {
  strings:
    $key_3e5f = { 69 2d [2] 5b 0f [2] 5d 3a [2] 73 3a [2] 4c 26 }

  condition:
    any of them
}