rule TTP_XOR_WriteProcessMemory_c9df {
  strings:
    $key_c9df = { 9e ad [2] ac 8f [2] aa ba [2] 84 ba [2] bb a6 }

  condition:
    any of them
}