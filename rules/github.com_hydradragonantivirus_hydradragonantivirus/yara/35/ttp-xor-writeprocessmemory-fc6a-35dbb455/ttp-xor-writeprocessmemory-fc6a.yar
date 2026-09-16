rule TTP_XOR_WriteProcessMemory_fc6a {
  strings:
    $key_fc6a = { ab 18 [2] 99 3a [2] 9f 0f [2] b1 0f [2] 8e 13 }

  condition:
    any of them
}