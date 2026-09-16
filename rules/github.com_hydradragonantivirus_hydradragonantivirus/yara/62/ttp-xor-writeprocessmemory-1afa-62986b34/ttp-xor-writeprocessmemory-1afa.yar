rule TTP_XOR_WriteProcessMemory_1afa {
  strings:
    $key_1afa = { 4d 88 [2] 7f aa [2] 79 9f [2] 57 9f [2] 68 83 }

  condition:
    any of them
}