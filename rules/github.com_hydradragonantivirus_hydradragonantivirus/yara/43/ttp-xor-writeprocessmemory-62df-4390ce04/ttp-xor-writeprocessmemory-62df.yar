rule TTP_XOR_WriteProcessMemory_62df {
  strings:
    $key_62df = { 35 ad [2] 07 8f [2] 01 ba [2] 2f ba [2] 10 a6 }

  condition:
    any of them
}