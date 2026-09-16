rule TTP_XOR_WriteProcessMemory_52bf {
  strings:
    $key_52bf = { 05 cd [2] 37 ef [2] 31 da [2] 1f da [2] 20 c6 }

  condition:
    any of them
}