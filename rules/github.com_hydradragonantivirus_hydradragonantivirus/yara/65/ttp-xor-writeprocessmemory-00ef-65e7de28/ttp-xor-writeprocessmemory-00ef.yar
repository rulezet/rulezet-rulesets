rule TTP_XOR_WriteProcessMemory_00ef {
  strings:
    $key_00ef = { 57 9d [2] 65 bf [2] 63 8a [2] 4d 8a [2] 72 96 }

  condition:
    any of them
}