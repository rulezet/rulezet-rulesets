rule TTP_XOR_WriteProcessMemory_4fda {
  strings:
    $key_4fda = { 18 a8 [2] 2a 8a [2] 2c bf [2] 02 bf [2] 3d a3 }

  condition:
    any of them
}