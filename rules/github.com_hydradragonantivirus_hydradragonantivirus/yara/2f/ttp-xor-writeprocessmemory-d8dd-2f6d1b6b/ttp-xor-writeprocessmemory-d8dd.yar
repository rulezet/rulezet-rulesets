rule TTP_XOR_WriteProcessMemory_d8dd {
  strings:
    $key_d8dd = { 8f af [2] bd 8d [2] bb b8 [2] 95 b8 [2] aa a4 }

  condition:
    any of them
}