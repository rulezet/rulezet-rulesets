rule TTP_XOR_WriteProcessMemory_942f {
  strings:
    $key_942f = { c3 5d [2] f1 7f [2] f7 4a [2] d9 4a [2] e6 56 }

  condition:
    any of them
}