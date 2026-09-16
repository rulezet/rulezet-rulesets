rule TTP_XOR_WriteProcessMemory_43bf {
  strings:
    $key_43bf = { 14 cd [2] 26 ef [2] 20 da [2] 0e da [2] 31 c6 }

  condition:
    any of them
}