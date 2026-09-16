rule TTP_XOR_WriteProcessMemory_296f {
  strings:
    $key_296f = { 7e 1d [2] 4c 3f [2] 4a 0a [2] 64 0a [2] 5b 16 }

  condition:
    any of them
}