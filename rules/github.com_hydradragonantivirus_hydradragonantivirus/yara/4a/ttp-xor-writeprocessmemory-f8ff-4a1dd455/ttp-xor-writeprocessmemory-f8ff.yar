rule TTP_XOR_WriteProcessMemory_f8ff {
  strings:
    $key_f8ff = { af 8d [2] 9d af [2] 9b 9a [2] b5 9a [2] 8a 86 }

  condition:
    any of them
}