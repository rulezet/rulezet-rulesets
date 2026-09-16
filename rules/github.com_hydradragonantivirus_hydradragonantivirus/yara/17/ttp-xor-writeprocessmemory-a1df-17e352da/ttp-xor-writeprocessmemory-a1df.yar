rule TTP_XOR_WriteProcessMemory_a1df {
  strings:
    $key_a1df = { f6 ad [2] c4 8f [2] c2 ba [2] ec ba [2] d3 a6 }

  condition:
    any of them
}