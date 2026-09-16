rule TTP_XOR_WriteProcessMemory_f9fa {
  strings:
    $key_f9fa = { ae 88 [2] 9c aa [2] 9a 9f [2] b4 9f [2] 8b 83 }

  condition:
    any of them
}