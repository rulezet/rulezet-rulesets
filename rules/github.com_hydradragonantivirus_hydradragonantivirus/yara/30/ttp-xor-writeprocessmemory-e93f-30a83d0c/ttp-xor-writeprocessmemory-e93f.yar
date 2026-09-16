rule TTP_XOR_WriteProcessMemory_e93f {
  strings:
    $key_e93f = { be 4d [2] 8c 6f [2] 8a 5a [2] a4 5a [2] 9b 46 }

  condition:
    any of them
}