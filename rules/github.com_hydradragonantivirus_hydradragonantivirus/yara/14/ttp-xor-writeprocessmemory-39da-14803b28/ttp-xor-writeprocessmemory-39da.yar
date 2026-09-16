rule TTP_XOR_WriteProcessMemory_39da {
  strings:
    $key_39da = { 6e a8 [2] 5c 8a [2] 5a bf [2] 74 bf [2] 4b a3 }

  condition:
    any of them
}