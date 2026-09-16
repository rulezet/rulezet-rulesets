rule TTP_XOR_WriteProcessMemory_99da {
  strings:
    $key_99da = { ce a8 [2] fc 8a [2] fa bf [2] d4 bf [2] eb a3 }

  condition:
    any of them
}