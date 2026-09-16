rule TTP_XOR_WriteProcessMemory_1efa {
  strings:
    $key_1efa = { 49 88 [2] 7b aa [2] 7d 9f [2] 53 9f [2] 6c 83 }

  condition:
    any of them
}