rule TTP_XOR_WriteProcessMemory_690f {
  strings:
    $key_690f = { 3e 7d [2] 0c 5f [2] 0a 6a [2] 24 6a [2] 1b 76 }

  condition:
    any of them
}