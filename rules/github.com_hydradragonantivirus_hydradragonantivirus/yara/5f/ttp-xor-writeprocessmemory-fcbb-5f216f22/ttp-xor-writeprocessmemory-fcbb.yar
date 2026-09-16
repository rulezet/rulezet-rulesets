rule TTP_XOR_WriteProcessMemory_fcbb {
  strings:
    $key_fcbb = { ab c9 [2] 99 eb [2] 9f de [2] b1 de [2] 8e c2 }

  condition:
    any of them
}