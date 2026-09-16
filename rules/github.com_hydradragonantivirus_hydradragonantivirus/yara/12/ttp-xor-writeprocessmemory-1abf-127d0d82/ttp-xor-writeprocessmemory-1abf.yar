rule TTP_XOR_WriteProcessMemory_1abf {
  strings:
    $key_1abf = { 4d cd [2] 7f ef [2] 79 da [2] 57 da [2] 68 c6 }

  condition:
    any of them
}