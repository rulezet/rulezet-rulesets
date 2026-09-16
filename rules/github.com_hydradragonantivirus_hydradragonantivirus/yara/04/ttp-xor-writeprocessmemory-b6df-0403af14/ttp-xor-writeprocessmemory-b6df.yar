rule TTP_XOR_WriteProcessMemory_b6df {
  strings:
    $key_b6df = { e1 ad [2] d3 8f [2] d5 ba [2] fb ba [2] c4 a6 }

  condition:
    any of them
}