rule TTP_XOR_WriteProcessMemory_4b3f {
  strings:
    $key_4b3f = { 1c 4d [2] 2e 6f [2] 28 5a [2] 06 5a [2] 39 46 }

  condition:
    any of them
}