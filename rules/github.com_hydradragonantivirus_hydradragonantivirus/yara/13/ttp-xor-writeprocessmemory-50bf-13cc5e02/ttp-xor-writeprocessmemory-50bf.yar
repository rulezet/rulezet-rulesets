rule TTP_XOR_WriteProcessMemory_50bf {
  strings:
    $key_50bf = { 07 cd [2] 35 ef [2] 33 da [2] 1d da [2] 22 c6 }

  condition:
    any of them
}