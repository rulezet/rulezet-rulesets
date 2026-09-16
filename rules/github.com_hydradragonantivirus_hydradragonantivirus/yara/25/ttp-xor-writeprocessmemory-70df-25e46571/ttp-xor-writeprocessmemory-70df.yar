rule TTP_XOR_WriteProcessMemory_70df {
  strings:
    $key_70df = { 27 ad [2] 15 8f [2] 13 ba [2] 3d ba [2] 02 a6 }

  condition:
    any of them
}