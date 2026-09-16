rule TTP_XOR_WriteProcessMemory_38ff {
  strings:
    $key_38ff = { 6f 8d [2] 5d af [2] 5b 9a [2] 75 9a [2] 4a 86 }

  condition:
    any of them
}