rule TTP_XOR_WriteProcessMemory_922f {
  strings:
    $key_922f = { c5 5d [2] f7 7f [2] f1 4a [2] df 4a [2] e0 56 }

  condition:
    any of them
}