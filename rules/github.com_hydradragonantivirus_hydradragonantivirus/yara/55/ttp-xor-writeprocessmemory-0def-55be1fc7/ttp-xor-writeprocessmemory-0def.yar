rule TTP_XOR_WriteProcessMemory_0def {
  strings:
    $key_0def = { 5a 9d [2] 68 bf [2] 6e 8a [2] 40 8a [2] 7f 96 }

  condition:
    any of them
}