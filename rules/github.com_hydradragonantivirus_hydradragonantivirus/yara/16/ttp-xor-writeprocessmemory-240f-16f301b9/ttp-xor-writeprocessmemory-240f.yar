rule TTP_XOR_WriteProcessMemory_240f {
  strings:
    $key_240f = { 73 7d [2] 41 5f [2] 47 6a [2] 69 6a [2] 56 76 }

  condition:
    any of them
}