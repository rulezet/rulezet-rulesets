rule TTP_XOR_WriteProcessMemory_517f {
  strings:
    $key_517f = { 06 0d [2] 34 2f [2] 32 1a [2] 1c 1a [2] 23 06 }

  condition:
    any of them
}