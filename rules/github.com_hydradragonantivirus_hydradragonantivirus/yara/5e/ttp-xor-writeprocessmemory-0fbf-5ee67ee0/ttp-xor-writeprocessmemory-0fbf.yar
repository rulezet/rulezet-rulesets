rule TTP_XOR_WriteProcessMemory_0fbf {
  strings:
    $key_0fbf = { 58 cd [2] 6a ef [2] 6c da [2] 42 da [2] 7d c6 }

  condition:
    any of them
}