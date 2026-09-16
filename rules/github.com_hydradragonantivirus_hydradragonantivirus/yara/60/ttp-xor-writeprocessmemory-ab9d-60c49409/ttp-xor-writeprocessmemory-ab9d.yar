rule TTP_XOR_WriteProcessMemory_ab9d {
  strings:
    $key_ab9d = { fc ef [2] ce cd [2] c8 f8 [2] e6 f8 [2] d9 e4 }

  condition:
    any of them
}