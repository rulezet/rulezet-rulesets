rule TTP_XOR_WriteProcessMemory_a7fa {
  strings:
    $key_a7fa = { f0 88 [2] c2 aa [2] c4 9f [2] ea 9f [2] d5 83 }

  condition:
    any of them
}