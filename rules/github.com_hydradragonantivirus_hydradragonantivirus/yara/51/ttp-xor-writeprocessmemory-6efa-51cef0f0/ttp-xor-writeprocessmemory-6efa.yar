rule TTP_XOR_WriteProcessMemory_6efa {
  strings:
    $key_6efa = { 39 88 [2] 0b aa [2] 0d 9f [2] 23 9f [2] 1c 83 }

  condition:
    any of them
}