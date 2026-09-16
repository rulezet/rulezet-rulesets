rule TTP_XOR_WriteProcessMemory_33bf {
  strings:
    $key_33bf = { 64 cd [2] 56 ef [2] 50 da [2] 7e da [2] 41 c6 }

  condition:
    any of them
}