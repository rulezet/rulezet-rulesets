rule TTP_XOR_WriteProcessMemory_330f {
  strings:
    $key_330f = { 64 7d [2] 56 5f [2] 50 6a [2] 7e 6a [2] 41 76 }

  condition:
    any of them
}