rule TTP_XOR_WriteProcessMemory_049d {
  strings:
    $key_049d = { 53 ef [2] 61 cd [2] 67 f8 [2] 49 f8 [2] 76 e4 }

  condition:
    any of them
}