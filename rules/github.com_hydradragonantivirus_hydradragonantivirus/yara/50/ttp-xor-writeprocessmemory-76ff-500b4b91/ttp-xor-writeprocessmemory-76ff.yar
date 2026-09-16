rule TTP_XOR_WriteProcessMemory_76ff {
  strings:
    $key_76ff = { 21 8d [2] 13 af [2] 15 9a [2] 3b 9a [2] 04 86 }

  condition:
    any of them
}