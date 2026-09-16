rule TTP_XOR_WriteProcessMemory_871a {
  strings:
    $key_871a = { d0 68 [2] e2 4a [2] e4 7f [2] ca 7f [2] f5 63 }

  condition:
    any of them
}