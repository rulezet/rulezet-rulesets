rule TTP_XOR_WriteProcessMemory_132f {
  strings:
    $key_132f = { 44 5d [2] 76 7f [2] 70 4a [2] 5e 4a [2] 61 56 }

  condition:
    any of them
}