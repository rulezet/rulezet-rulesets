rule TTP_XOR_WriteProcessMemory_32bf {
  strings:
    $key_32bf = { 65 cd [2] 57 ef [2] 51 da [2] 7f da [2] 40 c6 }

  condition:
    any of them
}