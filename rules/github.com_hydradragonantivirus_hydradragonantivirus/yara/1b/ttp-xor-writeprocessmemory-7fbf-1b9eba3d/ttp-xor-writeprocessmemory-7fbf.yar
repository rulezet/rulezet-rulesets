rule TTP_XOR_WriteProcessMemory_7fbf {
  strings:
    $key_7fbf = { 28 cd [2] 1a ef [2] 1c da [2] 32 da [2] 0d c6 }

  condition:
    any of them
}