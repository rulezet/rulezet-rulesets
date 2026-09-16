rule TTP_XOR_WriteProcessMemory_24df {
  strings:
    $key_24df = { 73 ad [2] 41 8f [2] 47 ba [2] 69 ba [2] 56 a6 }

  condition:
    any of them
}