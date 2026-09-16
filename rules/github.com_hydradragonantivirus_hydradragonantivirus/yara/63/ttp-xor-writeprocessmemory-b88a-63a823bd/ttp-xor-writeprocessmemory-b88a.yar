rule TTP_XOR_WriteProcessMemory_b88a {
  strings:
    $key_b88a = { ef f8 [2] dd da [2] db ef [2] f5 ef [2] ca f3 }

  condition:
    any of them
}