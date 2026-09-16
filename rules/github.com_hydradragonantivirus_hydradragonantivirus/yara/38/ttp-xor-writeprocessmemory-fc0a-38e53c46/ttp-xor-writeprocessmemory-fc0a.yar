rule TTP_XOR_WriteProcessMemory_fc0a {
  strings:
    $key_fc0a = { ab 78 [2] 99 5a [2] 9f 6f [2] b1 6f [2] 8e 73 }

  condition:
    any of them
}