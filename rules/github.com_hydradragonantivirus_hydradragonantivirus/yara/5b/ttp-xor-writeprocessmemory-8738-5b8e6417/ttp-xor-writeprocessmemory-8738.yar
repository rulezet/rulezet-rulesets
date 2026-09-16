rule TTP_XOR_WriteProcessMemory_8738 {
  strings:
    $key_8738 = { d0 4a [2] e2 68 [2] e4 5d [2] ca 5d [2] f5 41 }

  condition:
    any of them
}