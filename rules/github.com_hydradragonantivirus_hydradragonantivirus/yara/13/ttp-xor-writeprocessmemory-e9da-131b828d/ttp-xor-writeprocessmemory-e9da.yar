rule TTP_XOR_WriteProcessMemory_e9da {
  strings:
    $key_e9da = { be a8 [2] 8c 8a [2] 8a bf [2] a4 bf [2] 9b a3 }

  condition:
    any of them
}