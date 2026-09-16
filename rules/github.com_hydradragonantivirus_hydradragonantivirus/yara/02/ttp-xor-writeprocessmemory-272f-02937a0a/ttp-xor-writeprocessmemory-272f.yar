rule TTP_XOR_WriteProcessMemory_272f {
  strings:
    $key_272f = { 70 5d [2] 42 7f [2] 44 4a [2] 6a 4a [2] 55 56 }

  condition:
    any of them
}