rule TTP_XOR_WriteProcessMemory_afda {
  strings:
    $key_afda = { f8 a8 [2] ca 8a [2] cc bf [2] e2 bf [2] dd a3 }

  condition:
    any of them
}