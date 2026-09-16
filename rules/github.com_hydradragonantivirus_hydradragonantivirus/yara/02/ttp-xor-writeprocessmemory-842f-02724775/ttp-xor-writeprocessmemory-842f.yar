rule TTP_XOR_WriteProcessMemory_842f {
  strings:
    $key_842f = { d3 5d [2] e1 7f [2] e7 4a [2] c9 4a [2] f6 56 }

  condition:
    any of them
}