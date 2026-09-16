rule TTP_XOR_WriteProcessMemory_fcea {
  strings:
    $key_fcea = { ab 98 [2] 99 ba [2] 9f 8f [2] b1 8f [2] 8e 93 }

  condition:
    any of them
}