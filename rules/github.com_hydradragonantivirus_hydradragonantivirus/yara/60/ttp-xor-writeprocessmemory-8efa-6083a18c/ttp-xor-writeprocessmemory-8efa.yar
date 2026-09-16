rule TTP_XOR_WriteProcessMemory_8efa {
  strings:
    $key_8efa = { d9 88 [2] eb aa [2] ed 9f [2] c3 9f [2] fc 83 }

  condition:
    any of them
}