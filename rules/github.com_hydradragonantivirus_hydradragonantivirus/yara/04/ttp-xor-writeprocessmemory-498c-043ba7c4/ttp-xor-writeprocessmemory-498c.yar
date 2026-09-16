rule TTP_XOR_WriteProcessMemory_498c {
  strings:
    $key_498c = { 1e fe [2] 2c dc [2] 2a e9 [2] 04 e9 [2] 3b f5 }

  condition:
    any of them
}