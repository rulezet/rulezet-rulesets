rule TTP_XOR_WriteProcessMemory_792f {
  strings:
    $key_792f = { 2e 5d [2] 1c 7f [2] 1a 4a [2] 34 4a [2] 0b 56 }

  condition:
    any of them
}