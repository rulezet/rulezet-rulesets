rule TTP_XOR_WriteProcessMemory_1c0f {
  strings:
    $key_1c0f = { 4b 7d [2] 79 5f [2] 7f 6a [2] 51 6a [2] 6e 76 }

  condition:
    any of them
}