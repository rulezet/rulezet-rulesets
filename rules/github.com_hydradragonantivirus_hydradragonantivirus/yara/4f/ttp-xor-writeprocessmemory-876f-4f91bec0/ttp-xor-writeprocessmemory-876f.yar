rule TTP_XOR_WriteProcessMemory_876f {
  strings:
    $key_876f = { d0 1d [2] e2 3f [2] e4 0a [2] ca 0a [2] f5 16 }

  condition:
    any of them
}