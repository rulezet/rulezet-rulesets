rule TTP_XOR_WriteProcessMemory_27df {
  strings:
    $key_27df = { 70 ad [2] 42 8f [2] 44 ba [2] 6a ba [2] 55 a6 }

  condition:
    any of them
}