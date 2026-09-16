rule TTP_XOR_WriteProcessMemory_691d {
  strings:
    $key_691d = { 3e 6f [2] 0c 4d [2] 0a 78 [2] 24 78 [2] 1b 64 }

  condition:
    any of them
}