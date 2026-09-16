rule TTP_XOR_WriteProcessMemory_2fbf {
  strings:
    $key_2fbf = { 78 cd [2] 4a ef [2] 4c da [2] 62 da [2] 5d c6 }

  condition:
    any of them
}