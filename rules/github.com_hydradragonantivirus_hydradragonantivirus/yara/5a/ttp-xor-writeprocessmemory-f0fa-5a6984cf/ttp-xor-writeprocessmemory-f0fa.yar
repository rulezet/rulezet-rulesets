rule TTP_XOR_WriteProcessMemory_f0fa {
  strings:
    $key_f0fa = { a7 88 [2] 95 aa [2] 93 9f [2] bd 9f [2] 82 83 }

  condition:
    any of them
}