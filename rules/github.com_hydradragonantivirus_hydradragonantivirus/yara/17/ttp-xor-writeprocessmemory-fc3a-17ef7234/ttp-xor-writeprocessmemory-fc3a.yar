rule TTP_XOR_WriteProcessMemory_fc3a {
  strings:
    $key_fc3a = { ab 48 [2] 99 6a [2] 9f 5f [2] b1 5f [2] 8e 43 }

  condition:
    any of them
}