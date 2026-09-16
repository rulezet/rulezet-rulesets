rule TTP_XOR_WriteProcessMemory_75ef {
  strings:
    $key_75ef = { 22 9d [2] 10 bf [2] 16 8a [2] 38 8a [2] 07 96 }

  condition:
    any of them
}