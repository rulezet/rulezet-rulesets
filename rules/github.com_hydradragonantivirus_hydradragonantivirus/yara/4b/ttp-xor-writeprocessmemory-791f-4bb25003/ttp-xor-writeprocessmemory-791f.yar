rule TTP_XOR_WriteProcessMemory_791f {
  strings:
    $key_791f = { 2e 6d [2] 1c 4f [2] 1a 7a [2] 34 7a [2] 0b 66 }

  condition:
    any of them
}