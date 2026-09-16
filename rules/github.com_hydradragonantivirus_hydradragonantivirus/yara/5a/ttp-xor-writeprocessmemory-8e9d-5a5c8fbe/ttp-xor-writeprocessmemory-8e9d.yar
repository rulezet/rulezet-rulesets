rule TTP_XOR_WriteProcessMemory_8e9d {
  strings:
    $key_8e9d = { d9 ef [2] eb cd [2] ed f8 [2] c3 f8 [2] fc e4 }

  condition:
    any of them
}