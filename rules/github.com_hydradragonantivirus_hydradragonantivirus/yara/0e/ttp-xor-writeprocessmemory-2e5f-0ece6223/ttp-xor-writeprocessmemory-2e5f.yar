rule TTP_XOR_WriteProcessMemory_2e5f {
  strings:
    $key_2e5f = { 79 2d [2] 4b 0f [2] 4d 3a [2] 63 3a [2] 5c 26 }

  condition:
    any of them
}