rule TTP_XOR_WriteProcessMemory_9f9d {
  strings:
    $key_9f9d = { c8 ef [2] fa cd [2] fc f8 [2] d2 f8 [2] ed e4 }

  condition:
    any of them
}