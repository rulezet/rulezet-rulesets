rule TTP_XOR_WriteProcessMemory_37da {
  strings:
    $key_37da = { 60 a8 [2] 52 8a [2] 54 bf [2] 7a bf [2] 45 a3 }

  condition:
    any of them
}