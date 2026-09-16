rule TTP_XOR_WriteProcessMemory_dcda {
  strings:
    $key_dcda = { 8b a8 [2] b9 8a [2] bf bf [2] 91 bf [2] ae a3 }

  condition:
    any of them
}