rule TTP_XOR_WriteProcessMemory_241d {
  strings:
    $key_241d = { 73 6f [2] 41 4d [2] 47 78 [2] 69 78 [2] 56 64 }

  condition:
    any of them
}