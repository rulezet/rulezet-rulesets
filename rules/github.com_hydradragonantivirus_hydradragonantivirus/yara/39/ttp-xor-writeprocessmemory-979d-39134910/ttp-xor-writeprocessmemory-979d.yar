rule TTP_XOR_WriteProcessMemory_979d {
  strings:
    $key_979d = { c0 ef [2] f2 cd [2] f4 f8 [2] da f8 [2] e5 e4 }

  condition:
    any of them
}