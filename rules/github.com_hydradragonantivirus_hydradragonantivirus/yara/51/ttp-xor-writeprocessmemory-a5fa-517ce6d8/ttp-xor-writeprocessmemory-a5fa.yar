rule TTP_XOR_WriteProcessMemory_a5fa {
  strings:
    $key_a5fa = { f2 88 [2] c0 aa [2] c6 9f [2] e8 9f [2] d7 83 }

  condition:
    any of them
}