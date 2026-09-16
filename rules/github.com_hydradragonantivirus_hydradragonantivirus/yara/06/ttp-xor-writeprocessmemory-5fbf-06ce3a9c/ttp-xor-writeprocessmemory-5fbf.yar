rule TTP_XOR_WriteProcessMemory_5fbf {
  strings:
    $key_5fbf = { 08 cd [2] 3a ef [2] 3c da [2] 12 da [2] 2d c6 }

  condition:
    any of them
}