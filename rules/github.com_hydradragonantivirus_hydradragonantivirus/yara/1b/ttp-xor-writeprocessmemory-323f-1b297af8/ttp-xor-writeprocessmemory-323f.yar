rule TTP_XOR_WriteProcessMemory_323f {
  strings:
    $key_323f = { 65 4d [2] 57 6f [2] 51 5a [2] 7f 5a [2] 40 46 }

  condition:
    any of them
}