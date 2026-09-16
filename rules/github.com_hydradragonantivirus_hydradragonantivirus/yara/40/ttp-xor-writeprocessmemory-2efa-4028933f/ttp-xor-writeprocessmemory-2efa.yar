rule TTP_XOR_WriteProcessMemory_2efa {
  strings:
    $key_2efa = { 79 88 [2] 4b aa [2] 4d 9f [2] 63 9f [2] 5c 83 }

  condition:
    any of them
}