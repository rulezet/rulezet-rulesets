rule TTP_XOR_WriteProcessMemory_691f {
  strings:
    $key_691f = { 3e 6d [2] 0c 4f [2] 0a 7a [2] 24 7a [2] 1b 66 }

  condition:
    any of them
}