rule TTP_XOR_WriteProcessMemory_842a {
  strings:
    $key_842a = { d3 58 [2] e1 7a [2] e7 4f [2] c9 4f [2] f6 53 }

  condition:
    any of them
}