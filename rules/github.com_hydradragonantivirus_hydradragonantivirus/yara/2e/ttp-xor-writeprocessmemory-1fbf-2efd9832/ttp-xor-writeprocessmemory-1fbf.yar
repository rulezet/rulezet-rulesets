rule TTP_XOR_WriteProcessMemory_1fbf {
  strings:
    $key_1fbf = { 48 cd [2] 7a ef [2] 7c da [2] 52 da [2] 6d c6 }

  condition:
    any of them
}