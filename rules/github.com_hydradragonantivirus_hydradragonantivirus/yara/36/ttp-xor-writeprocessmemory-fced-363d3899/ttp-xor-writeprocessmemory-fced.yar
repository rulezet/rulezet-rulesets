rule TTP_XOR_WriteProcessMemory_fced {
  strings:
    $key_fced = { ab 9f [2] 99 bd [2] 9f 88 [2] b1 88 [2] 8e 94 }

  condition:
    any of them
}