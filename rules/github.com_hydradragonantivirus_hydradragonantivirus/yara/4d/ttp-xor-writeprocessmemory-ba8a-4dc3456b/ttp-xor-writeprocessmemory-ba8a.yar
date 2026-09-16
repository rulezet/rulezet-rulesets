rule TTP_XOR_WriteProcessMemory_ba8a {
  strings:
    $key_ba8a = { ed f8 [2] df da [2] d9 ef [2] f7 ef [2] c8 f3 }

  condition:
    any of them
}