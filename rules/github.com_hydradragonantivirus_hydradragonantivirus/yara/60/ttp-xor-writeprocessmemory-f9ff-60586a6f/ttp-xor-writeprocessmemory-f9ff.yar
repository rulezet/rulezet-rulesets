rule TTP_XOR_WriteProcessMemory_f9ff {
  strings:
    $key_f9ff = { ae 8d [2] 9c af [2] 9a 9a [2] b4 9a [2] 8b 86 }

  condition:
    any of them
}