rule TTP_XOR_WriteProcessMemory_ebca {
  strings:
    $key_ebca = { bc b8 [2] 8e 9a [2] 88 af [2] a6 af [2] 99 b3 }

  condition:
    any of them
}