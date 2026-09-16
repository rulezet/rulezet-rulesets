rule TTP_XOR_WriteProcessMemory_31ff {
  strings:
    $key_31ff = { 66 8d [2] 54 af [2] 52 9a [2] 7c 9a [2] 43 86 }

  condition:
    any of them
}