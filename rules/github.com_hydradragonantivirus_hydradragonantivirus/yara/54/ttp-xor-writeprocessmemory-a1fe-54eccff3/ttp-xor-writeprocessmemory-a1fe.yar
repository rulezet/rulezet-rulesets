rule TTP_XOR_WriteProcessMemory_a1fe {
  strings:
    $key_a1fe = { f6 8c [2] c4 ae [2] c2 9b [2] ec 9b [2] d3 87 }

  condition:
    any of them
}