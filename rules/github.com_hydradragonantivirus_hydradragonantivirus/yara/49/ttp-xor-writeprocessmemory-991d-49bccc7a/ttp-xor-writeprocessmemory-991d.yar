rule TTP_XOR_WriteProcessMemory_991d {
  strings:
    $key_991d = { ce 6f [2] fc 4d [2] fa 78 [2] d4 78 [2] eb 64 }

  condition:
    any of them
}