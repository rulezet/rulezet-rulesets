rule TTP_XOR_WriteProcessMemory_7efa {
  strings:
    $key_7efa = { 29 88 [2] 1b aa [2] 1d 9f [2] 33 9f [2] 0c 83 }

  condition:
    any of them
}