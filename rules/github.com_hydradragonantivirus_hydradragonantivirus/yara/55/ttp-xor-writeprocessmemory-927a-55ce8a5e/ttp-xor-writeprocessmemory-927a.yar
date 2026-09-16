rule TTP_XOR_WriteProcessMemory_927a {
  strings:
    $key_927a = { c5 08 [2] f7 2a [2] f1 1f [2] df 1f [2] e0 03 }

  condition:
    any of them
}