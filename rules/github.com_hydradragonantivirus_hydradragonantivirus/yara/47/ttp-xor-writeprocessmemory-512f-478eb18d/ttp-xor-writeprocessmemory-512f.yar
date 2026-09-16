rule TTP_XOR_WriteProcessMemory_512f {
  strings:
    $key_512f = { 06 5d [2] 34 7f [2] 32 4a [2] 1c 4a [2] 23 56 }

  condition:
    any of them
}