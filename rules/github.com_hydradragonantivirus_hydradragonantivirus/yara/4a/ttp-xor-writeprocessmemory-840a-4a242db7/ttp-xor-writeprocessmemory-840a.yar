rule TTP_XOR_WriteProcessMemory_840a {
  strings:
    $key_840a = { d3 78 [2] e1 5a [2] e7 6f [2] c9 6f [2] f6 73 }

  condition:
    any of them
}