rule TTP_XOR_WriteProcessMemory_02ff {
  strings:
    $key_02ff = { 55 8d [2] 67 af [2] 61 9a [2] 4f 9a [2] 70 86 }

  condition:
    any of them
}