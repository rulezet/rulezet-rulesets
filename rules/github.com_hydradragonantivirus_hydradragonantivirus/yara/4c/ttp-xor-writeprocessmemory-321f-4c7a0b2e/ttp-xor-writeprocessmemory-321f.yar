rule TTP_XOR_WriteProcessMemory_321f {
  strings:
    $key_321f = { 65 6d [2] 57 4f [2] 51 7a [2] 7f 7a [2] 40 66 }

  condition:
    any of them
}