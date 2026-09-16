rule TTP_XOR_WriteProcessMemory_259d {
  strings:
    $key_259d = { 72 ef [2] 40 cd [2] 46 f8 [2] 68 f8 [2] 57 e4 }

  condition:
    any of them
}