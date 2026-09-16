rule TTP_XOR_WriteProcessMemory_330d {
  strings:
    $key_330d = { 64 7f [2] 56 5d [2] 50 68 [2] 7e 68 [2] 41 74 }

  condition:
    any of them
}