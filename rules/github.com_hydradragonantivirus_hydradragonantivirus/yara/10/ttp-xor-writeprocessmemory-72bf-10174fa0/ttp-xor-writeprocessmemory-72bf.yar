rule TTP_XOR_WriteProcessMemory_72bf {
  strings:
    $key_72bf = { 25 cd [2] 17 ef [2] 11 da [2] 3f da [2] 00 c6 }

  condition:
    any of them
}