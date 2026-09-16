rule TTP_XOR_WriteProcessMemory_ca9d {
  strings:
    $key_ca9d = { 9d ef [2] af cd [2] a9 f8 [2] 87 f8 [2] b8 e4 }

  condition:
    any of them
}