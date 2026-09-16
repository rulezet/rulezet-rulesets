rule TTP_XOR_WriteProcessMemory_3abf {
  strings:
    $key_3abf = { 6d cd [2] 5f ef [2] 59 da [2] 77 da [2] 48 c6 }

  condition:
    any of them
}