rule TTP_XOR_WriteProcessMemory_93ca {
  strings:
    $key_93ca = { c4 b8 [2] f6 9a [2] f0 af [2] de af [2] e1 b3 }

  condition:
    any of them
}