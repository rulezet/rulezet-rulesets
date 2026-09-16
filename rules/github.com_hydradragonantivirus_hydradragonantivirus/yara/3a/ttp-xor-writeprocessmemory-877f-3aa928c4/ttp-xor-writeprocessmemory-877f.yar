rule TTP_XOR_WriteProcessMemory_877f {
  strings:
    $key_877f = { d0 0d [2] e2 2f [2] e4 1a [2] ca 1a [2] f5 06 }

  condition:
    any of them
}