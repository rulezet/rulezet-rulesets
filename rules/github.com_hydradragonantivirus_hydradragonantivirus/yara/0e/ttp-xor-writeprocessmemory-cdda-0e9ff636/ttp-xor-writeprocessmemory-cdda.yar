rule TTP_XOR_WriteProcessMemory_cdda {
  strings:
    $key_cdda = { 9a a8 [2] a8 8a [2] ae bf [2] 80 bf [2] bf a3 }

  condition:
    any of them
}