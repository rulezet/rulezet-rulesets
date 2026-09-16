rule TTP_XOR_WriteProcessMemory_fffa {
  strings:
    $key_fffa = { a8 88 [2] 9a aa [2] 9c 9f [2] b2 9f [2] 8d 83 }

  condition:
    any of them
}