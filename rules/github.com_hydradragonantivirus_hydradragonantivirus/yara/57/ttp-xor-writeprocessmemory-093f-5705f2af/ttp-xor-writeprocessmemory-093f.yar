rule TTP_XOR_WriteProcessMemory_093f {
  strings:
    $key_093f = { 5e 4d [2] 6c 6f [2] 6a 5a [2] 44 5a [2] 7b 46 }

  condition:
    any of them
}