rule TTP_XOR_WriteProcessMemory_23da {
  strings:
    $key_23da = { 74 a8 [2] 46 8a [2] 40 bf [2] 6e bf [2] 51 a3 }

  condition:
    any of them
}