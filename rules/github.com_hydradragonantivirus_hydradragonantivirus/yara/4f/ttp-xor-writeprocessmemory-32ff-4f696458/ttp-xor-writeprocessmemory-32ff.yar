rule TTP_XOR_WriteProcessMemory_32ff {
  strings:
    $key_32ff = { 65 8d [2] 57 af [2] 51 9a [2] 7f 9a [2] 40 86 }

  condition:
    any of them
}