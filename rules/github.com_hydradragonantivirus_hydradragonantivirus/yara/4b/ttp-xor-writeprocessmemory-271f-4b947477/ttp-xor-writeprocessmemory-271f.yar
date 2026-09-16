rule TTP_XOR_WriteProcessMemory_271f {
  strings:
    $key_271f = { 70 6d [2] 42 4f [2] 44 7a [2] 6a 7a [2] 55 66 }

  condition:
    any of them
}