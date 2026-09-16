rule TTP_XOR_WriteProcessMemory_adcc {
  strings:
    $key_adcc = { fa be [2] c8 9c [2] ce a9 [2] e0 a9 [2] df b5 }

  condition:
    any of them
}