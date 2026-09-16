rule TTP_XOR_WriteProcessMemory_5afa {
  strings:
    $key_5afa = { 0d 88 [2] 3f aa [2] 39 9f [2] 17 9f [2] 28 83 }

  condition:
    any of them
}