rule TTP_XOR_WriteProcessMemory_fc0f {
  strings:
    $key_fc0f = { ab 7d [2] 99 5f [2] 9f 6a [2] b1 6a [2] 8e 76 }

  condition:
    any of them
}