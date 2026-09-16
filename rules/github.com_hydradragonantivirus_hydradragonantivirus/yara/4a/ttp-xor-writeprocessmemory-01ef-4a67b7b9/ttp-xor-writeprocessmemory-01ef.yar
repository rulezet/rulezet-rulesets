rule TTP_XOR_WriteProcessMemory_01ef {
  strings:
    $key_01ef = { 56 9d [2] 64 bf [2] 62 8a [2] 4c 8a [2] 73 96 }

  condition:
    any of them
}