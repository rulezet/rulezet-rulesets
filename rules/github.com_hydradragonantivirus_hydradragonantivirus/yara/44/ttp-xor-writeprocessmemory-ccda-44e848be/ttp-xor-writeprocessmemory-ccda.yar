rule TTP_XOR_WriteProcessMemory_ccda {
  strings:
    $key_ccda = { 9b a8 [2] a9 8a [2] af bf [2] 81 bf [2] be a3 }

  condition:
    any of them
}