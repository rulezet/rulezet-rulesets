rule TTP_XOR_WriteProcessMemory_af9d {
  strings:
    $key_af9d = { f8 ef [2] ca cd [2] cc f8 [2] e2 f8 [2] dd e4 }

  condition:
    any of them
}