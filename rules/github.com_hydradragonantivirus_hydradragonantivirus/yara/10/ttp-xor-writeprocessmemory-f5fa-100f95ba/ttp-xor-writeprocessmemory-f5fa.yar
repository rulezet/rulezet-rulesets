rule TTP_XOR_WriteProcessMemory_f5fa {
  strings:
    $key_f5fa = { a2 88 [2] 90 aa [2] 96 9f [2] b8 9f [2] 87 83 }

  condition:
    any of them
}