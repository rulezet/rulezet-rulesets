rule TTP_XOR_WriteProcessMemory_191d {
  strings:
    $key_191d = { 4e 6f [2] 7c 4d [2] 7a 78 [2] 54 78 [2] 6b 64 }

  condition:
    any of them
}