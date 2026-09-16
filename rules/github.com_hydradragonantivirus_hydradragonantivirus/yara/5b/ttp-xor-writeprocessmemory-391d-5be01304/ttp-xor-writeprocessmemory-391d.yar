rule TTP_XOR_WriteProcessMemory_391d {
  strings:
    $key_391d = { 6e 6f [2] 5c 4d [2] 5a 78 [2] 74 78 [2] 4b 64 }

  condition:
    any of them
}