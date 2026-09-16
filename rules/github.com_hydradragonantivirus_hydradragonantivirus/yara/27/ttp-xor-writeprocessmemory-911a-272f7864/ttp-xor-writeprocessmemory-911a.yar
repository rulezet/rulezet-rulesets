rule TTP_XOR_WriteProcessMemory_911a {
  strings:
    $key_911a = { c6 68 [2] f4 4a [2] f2 7f [2] dc 7f [2] e3 63 }

  condition:
    any of them
}