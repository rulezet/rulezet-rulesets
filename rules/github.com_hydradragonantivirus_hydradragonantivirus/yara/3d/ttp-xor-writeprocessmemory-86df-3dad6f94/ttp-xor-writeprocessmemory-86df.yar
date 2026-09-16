rule TTP_XOR_WriteProcessMemory_86df {
  strings:
    $key_86df = { d1 ad [2] e3 8f [2] e5 ba [2] cb ba [2] f4 a6 }

  condition:
    any of them
}