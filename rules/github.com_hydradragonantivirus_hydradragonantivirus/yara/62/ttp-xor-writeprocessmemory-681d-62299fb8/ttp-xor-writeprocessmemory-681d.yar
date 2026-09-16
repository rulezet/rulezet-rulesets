rule TTP_XOR_WriteProcessMemory_681d {
  strings:
    $key_681d = { 3f 6f [2] 0d 4d [2] 0b 78 [2] 25 78 [2] 1a 64 }

  condition:
    any of them
}