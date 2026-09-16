rule TTP_XOR_WriteProcessMemory_06ff {
  strings:
    $key_06ff = { 51 8d [2] 63 af [2] 65 9a [2] 4b 9a [2] 74 86 }

  condition:
    any of them
}