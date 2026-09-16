rule TTP_XOR_WriteProcessMemory_4efa {
  strings:
    $key_4efa = { 19 88 [2] 2b aa [2] 2d 9f [2] 03 9f [2] 3c 83 }

  condition:
    any of them
}