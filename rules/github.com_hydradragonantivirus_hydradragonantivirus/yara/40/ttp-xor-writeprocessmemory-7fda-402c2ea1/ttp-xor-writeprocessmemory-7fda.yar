rule TTP_XOR_WriteProcessMemory_7fda {
  strings:
    $key_7fda = { 28 a8 [2] 1a 8a [2] 1c bf [2] 32 bf [2] 0d a3 }

  condition:
    any of them
}