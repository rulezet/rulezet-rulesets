rule TTP_XOR_WriteProcessMemory_62ff {
  strings:
    $key_62ff = { 35 8d [2] 07 af [2] 01 9a [2] 2f 9a [2] 10 86 }

  condition:
    any of them
}