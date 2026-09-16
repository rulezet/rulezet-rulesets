rule TTP_XOR_WriteProcessMemory_09ff {
  strings:
    $key_09ff = { 5e 8d [2] 6c af [2] 6a 9a [2] 44 9a [2] 7b 86 }

  condition:
    any of them
}