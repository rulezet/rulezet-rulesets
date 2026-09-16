rule TTP_XOR_WriteProcessMemory_f6fa {
  strings:
    $key_f6fa = { a1 88 [2] 93 aa [2] 95 9f [2] bb 9f [2] 84 83 }

  condition:
    any of them
}