rule TTP_XOR_WriteProcessMemory_4afa {
  strings:
    $key_4afa = { 1d 88 [2] 2f aa [2] 29 9f [2] 07 9f [2] 38 83 }

  condition:
    any of them
}