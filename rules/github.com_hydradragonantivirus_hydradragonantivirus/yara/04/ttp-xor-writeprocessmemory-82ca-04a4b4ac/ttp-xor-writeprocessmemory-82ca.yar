rule TTP_XOR_WriteProcessMemory_82ca {
  strings:
    $key_82ca = { d5 b8 [2] e7 9a [2] e1 af [2] cf af [2] f0 b3 }

  condition:
    any of them
}