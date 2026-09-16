rule TTP_XOR_WriteProcessMemory_14df {
  strings:
    $key_14df = { 43 ad [2] 71 8f [2] 77 ba [2] 59 ba [2] 66 a6 }

  condition:
    any of them
}