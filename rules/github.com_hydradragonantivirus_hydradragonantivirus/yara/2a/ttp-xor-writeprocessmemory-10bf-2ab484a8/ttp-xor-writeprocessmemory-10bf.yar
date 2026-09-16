rule TTP_XOR_WriteProcessMemory_10bf {
  strings:
    $key_10bf = { 47 cd [2] 75 ef [2] 73 da [2] 5d da [2] 62 c6 }

  condition:
    any of them
}