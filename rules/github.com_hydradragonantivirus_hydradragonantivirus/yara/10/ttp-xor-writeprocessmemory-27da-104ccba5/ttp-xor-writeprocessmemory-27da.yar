rule TTP_XOR_WriteProcessMemory_27da {
  strings:
    $key_27da = { 70 a8 [2] 42 8a [2] 44 bf [2] 6a bf [2] 55 a3 }

  condition:
    any of them
}