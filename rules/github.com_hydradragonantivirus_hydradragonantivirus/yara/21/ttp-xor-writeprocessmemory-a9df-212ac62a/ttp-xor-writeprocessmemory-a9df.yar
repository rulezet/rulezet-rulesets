rule TTP_XOR_WriteProcessMemory_a9df {
  strings:
    $key_a9df = { fe ad [2] cc 8f [2] ca ba [2] e4 ba [2] db a6 }

  condition:
    any of them
}