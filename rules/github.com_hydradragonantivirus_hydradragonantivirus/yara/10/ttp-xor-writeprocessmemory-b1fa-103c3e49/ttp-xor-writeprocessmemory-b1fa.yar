rule TTP_XOR_WriteProcessMemory_b1fa {
  strings:
    $key_b1fa = { e6 88 [2] d4 aa [2] d2 9f [2] fc 9f [2] c3 83 }

  condition:
    any of them
}