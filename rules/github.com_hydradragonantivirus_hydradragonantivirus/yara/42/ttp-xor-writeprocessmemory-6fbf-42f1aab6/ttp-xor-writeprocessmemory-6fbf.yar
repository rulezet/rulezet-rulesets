rule TTP_XOR_WriteProcessMemory_6fbf {
  strings:
    $key_6fbf = { 38 cd [2] 0a ef [2] 0c da [2] 22 da [2] 1d c6 }

  condition:
    any of them
}