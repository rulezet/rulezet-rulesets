rule TTP_XOR_WriteProcessMemory_11bf {
  strings:
    $key_11bf = { 46 cd [2] 74 ef [2] 72 da [2] 5c da [2] 63 c6 }

  condition:
    any of them
}