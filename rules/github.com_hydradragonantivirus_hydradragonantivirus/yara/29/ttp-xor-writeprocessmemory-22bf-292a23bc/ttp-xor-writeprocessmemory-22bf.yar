rule TTP_XOR_WriteProcessMemory_22bf {
  strings:
    $key_22bf = { 75 cd [2] 47 ef [2] 41 da [2] 6f da [2] 50 c6 }

  condition:
    any of them
}