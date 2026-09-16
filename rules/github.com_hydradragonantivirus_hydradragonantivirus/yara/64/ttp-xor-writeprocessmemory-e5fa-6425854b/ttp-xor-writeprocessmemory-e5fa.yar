rule TTP_XOR_WriteProcessMemory_e5fa {
  strings:
    $key_e5fa = { b2 88 [2] 80 aa [2] 86 9f [2] a8 9f [2] 97 83 }

  condition:
    any of them
}