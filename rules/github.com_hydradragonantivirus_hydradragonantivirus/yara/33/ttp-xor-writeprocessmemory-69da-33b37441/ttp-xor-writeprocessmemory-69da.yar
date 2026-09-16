rule TTP_XOR_WriteProcessMemory_69da {
  strings:
    $key_69da = { 3e a8 [2] 0c 8a [2] 0a bf [2] 24 bf [2] 1b a3 }

  condition:
    any of them
}