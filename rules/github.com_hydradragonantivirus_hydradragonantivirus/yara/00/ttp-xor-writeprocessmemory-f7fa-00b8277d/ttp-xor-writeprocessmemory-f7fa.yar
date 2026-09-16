rule TTP_XOR_WriteProcessMemory_f7fa {
  strings:
    $key_f7fa = { a0 88 [2] 92 aa [2] 94 9f [2] ba 9f [2] 85 83 }

  condition:
    any of them
}